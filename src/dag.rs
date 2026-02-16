//! In-memory DAG index — fast graph traversal over record IDs.
//!
//! Stores only IDs and edges in memory, not full records.
//! Full records are fetched from the storage backend on demand.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::errors::{ElaraError, Result};

/// In-memory DAG index for fast traversal.
#[derive(Debug, Clone)]
pub struct DagIndex {
    /// parent_id -> set of child_ids
    children: HashMap<String, HashSet<String>>,
    /// child_id -> set of parent_ids
    parents: HashMap<String, HashSet<String>>,
    /// All known record IDs
    nodes: HashSet<String>,
    /// Record timestamps for ordering
    timestamps: HashMap<String, f64>,
}

impl DagIndex {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            parents: HashMap::new(),
            nodes: HashSet::new(),
            timestamps: HashMap::new(),
        }
    }

    /// Add a record to the index.
    pub fn insert(&mut self, id: String, parent_ids: Vec<String>, timestamp: f64) -> Result<()> {
        if self.nodes.contains(&id) {
            return Err(ElaraError::DuplicateRecord(id));
        }

        // Check parents exist
        for pid in &parent_ids {
            if !self.nodes.contains(pid) {
                return Err(ElaraError::MissingParent(pid.clone()));
            }
        }

        // Add edges
        for pid in &parent_ids {
            self.children
                .entry(pid.clone())
                .or_default()
                .insert(id.clone());
            self.parents
                .entry(id.clone())
                .or_default()
                .insert(pid.clone());
        }

        self.nodes.insert(id.clone());
        self.timestamps.insert(id, timestamp);
        Ok(())
    }

    /// Records with no children (frontier).
    pub fn tips(&self) -> Vec<String> {
        let mut tips: Vec<_> = self
            .nodes
            .iter()
            .filter(|id| {
                self.children
                    .get(*id)
                    .map_or(true, |c| c.is_empty())
            })
            .cloned()
            .collect();
        // Sort by timestamp descending
        tips.sort_by(|a, b| {
            let ta = self.timestamps.get(a).copied().unwrap_or(0.0);
            let tb = self.timestamps.get(b).copied().unwrap_or(0.0);
            tb.partial_cmp(&ta).unwrap()
        });
        tips
    }

    /// Records with no parents (genesis).
    pub fn roots(&self) -> Vec<String> {
        let mut roots: Vec<_> = self
            .nodes
            .iter()
            .filter(|id| {
                self.parents
                    .get(*id)
                    .map_or(true, |p| p.is_empty())
            })
            .cloned()
            .collect();
        roots.sort_by(|a, b| {
            let ta = self.timestamps.get(a).copied().unwrap_or(0.0);
            let tb = self.timestamps.get(b).copied().unwrap_or(0.0);
            ta.partial_cmp(&tb).unwrap()
        });
        roots
    }

    /// Direct parents of a record.
    pub fn parents(&self, id: &str) -> Vec<String> {
        self.parents
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Direct children of a record.
    pub fn children(&self, id: &str) -> Vec<String> {
        self.children
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// All ancestor IDs (transitive parents), BFS with depth limit.
    pub fn ancestors(&self, id: &str, max_depth: usize) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((id.to_string(), 0usize));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(parent_set) = self.parents.get(&current) {
                for pid in parent_set {
                    if visited.insert(pid.clone()) {
                        queue.push_back((pid.clone(), depth + 1));
                    }
                }
            }
        }

        visited
    }

    /// All descendant IDs (transitive children), BFS with depth limit.
    pub fn descendants(&self, id: &str, max_depth: usize) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((id.to_string(), 0usize));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(child_set) = self.children.get(&current) {
                for cid in child_set {
                    if visited.insert(cid.clone()) {
                        queue.push_back((cid.clone(), depth + 1));
                    }
                }
            }
        }

        visited
    }

    /// Check if a record exists in the index.
    pub fn contains(&self, id: &str) -> bool {
        self.nodes.contains(id)
    }

    /// Total number of records.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Total number of edges.
    pub fn edge_count(&self) -> usize {
        self.parents.values().map(|s| s.len()).sum()
    }
}

impl Default for DagIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_dag() {
        let dag = DagIndex::new();
        assert!(dag.is_empty());
        assert_eq!(dag.len(), 0);
        assert_eq!(dag.edge_count(), 0);
        assert!(dag.tips().is_empty());
        assert!(dag.roots().is_empty());
    }

    #[test]
    fn test_single_root() {
        let mut dag = DagIndex::new();
        dag.insert("r1".into(), vec![], 1.0).unwrap();
        assert_eq!(dag.len(), 1);
        assert_eq!(dag.roots(), vec!["r1"]);
        assert_eq!(dag.tips(), vec!["r1"]);
    }

    #[test]
    fn test_chain() {
        let mut dag = DagIndex::new();
        dag.insert("r1".into(), vec![], 1.0).unwrap();
        dag.insert("r2".into(), vec!["r1".into()], 2.0).unwrap();
        dag.insert("r3".into(), vec!["r2".into()], 3.0).unwrap();

        assert_eq!(dag.roots(), vec!["r1"]);
        assert_eq!(dag.tips(), vec!["r3"]);
        assert_eq!(dag.edge_count(), 2);
        assert_eq!(dag.parents("r3"), vec!["r2"]);
        assert_eq!(dag.children("r1"), vec!["r2"]);
    }

    #[test]
    fn test_branch_and_merge() {
        let mut dag = DagIndex::new();
        dag.insert("root".into(), vec![], 1.0).unwrap();
        dag.insert("left".into(), vec!["root".into()], 2.0).unwrap();
        dag.insert("right".into(), vec!["root".into()], 2.5).unwrap();
        dag.insert("merge".into(), vec!["left".into(), "right".into()], 3.0)
            .unwrap();

        assert_eq!(dag.roots(), vec!["root"]);
        assert_eq!(dag.tips(), vec!["merge"]);
        assert_eq!(dag.edge_count(), 4); // root->left, root->right, left->merge, right->merge

        let merge_parents: HashSet<String> = dag.parents("merge").into_iter().collect();
        assert!(merge_parents.contains("left"));
        assert!(merge_parents.contains("right"));
    }

    #[test]
    fn test_ancestors() {
        let mut dag = DagIndex::new();
        for i in 0..10 {
            let id = format!("r{i}");
            let parents = if i == 0 { vec![] } else { vec![format!("r{}", i - 1)] };
            dag.insert(id, parents, i as f64).unwrap();
        }

        let ancestors = dag.ancestors("r9", 100);
        assert_eq!(ancestors.len(), 9);
        assert!(ancestors.contains("r0"));
        assert!(ancestors.contains("r8"));
        assert!(!ancestors.contains("r9"));
    }

    #[test]
    fn test_ancestors_depth_limit() {
        let mut dag = DagIndex::new();
        for i in 0..10 {
            let id = format!("r{i}");
            let parents = if i == 0 { vec![] } else { vec![format!("r{}", i - 1)] };
            dag.insert(id, parents, i as f64).unwrap();
        }

        let ancestors = dag.ancestors("r9", 3);
        assert_eq!(ancestors.len(), 3); // r8, r7, r6
    }

    #[test]
    fn test_descendants() {
        let mut dag = DagIndex::new();
        dag.insert("a".into(), vec![], 1.0).unwrap();
        dag.insert("b".into(), vec!["a".into()], 2.0).unwrap();
        dag.insert("c".into(), vec!["b".into()], 3.0).unwrap();

        let desc = dag.descendants("a", 100);
        assert_eq!(desc.len(), 2);
        assert!(desc.contains("b"));
        assert!(desc.contains("c"));
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut dag = DagIndex::new();
        dag.insert("r1".into(), vec![], 1.0).unwrap();
        assert!(dag.insert("r1".into(), vec![], 2.0).is_err());
    }

    #[test]
    fn test_missing_parent() {
        let mut dag = DagIndex::new();
        assert!(dag.insert("r1".into(), vec!["nonexistent".into()], 1.0).is_err());
    }

    #[test]
    fn test_large_dag() {
        let mut dag = DagIndex::new();
        // Build a 10K node chain
        for i in 0..10_000 {
            let id = format!("n{i:05}");
            let parents = if i == 0 { vec![] } else { vec![format!("n{:05}", i - 1)] };
            dag.insert(id, parents, i as f64).unwrap();
        }
        assert_eq!(dag.len(), 10_000);
        assert_eq!(dag.edge_count(), 9_999);
    }
}
