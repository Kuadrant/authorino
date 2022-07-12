package cache

import (
	"fmt"
	"strings"
	"sync"

	"github.com/kuadrant/authorino/pkg/evaluators"
)

const (
	keyLabelsSeparator string = "."
	rootKeyLabel       string = "" // must differ `keyLabelsSeparator`
)

type Cache interface {
	Set(id string, key string, config evaluators.AuthConfig, override bool) error
	Get(key string) *evaluators.AuthConfig
	Delete(id string)
	List() []*evaluators.AuthConfig

	FindId(key string) (id string, found bool)
	FindKeys(id string) []string
}

func NewCache() Cache {
	return newAuthConfigTree()
}

type cacheEntry struct {
	Id         string
	AuthConfig evaluators.AuthConfig
}

// Cache of AuthConfigs structured as a radix tree.
// Each dot ('.') in the key induces a new level in the tree.
// Tree-based cache structures support wildcards ('*') in the keys.
// Wildcards match any value after the longest common path between the searched key and the levels of the tree.

func newAuthConfigTree() *authConfigTree {
	return &authConfigTree{
		mu:   sync.Mutex{},
		root: newTreeNode(rootKeyLabel, nil),
		keys: make(map[string][]string),
	}
}

type authConfigTree struct {
	mu   sync.Mutex
	root *treeNode
	keys map[string][]string
}

func (c *authConfigTree) Get(key string) *evaluators.AuthConfig {
	if entry := c.root.get(revertKey(key)); entry != nil {
		return &entry.AuthConfig
	}

	return nil
}

func (c *authConfigTree) Set(id, key string, config evaluators.AuthConfig, override bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &cacheEntry{
		Id:         id,
		AuthConfig: config,
	}
	err := c.root.set(revertKey(key), entry, override)
	if err == nil {
		c.keys[id] = append(c.keys[id], key)
	}
	return err
}

func (c *authConfigTree) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if keys, ok := c.keys[id]; ok {
		for _, key := range keys {
			if node, _ := c.root.longestCommonLabel(revertKey(key)); node != nil && node.entry != nil && node.entry.Id == id {
				node.entry = nil
			}
		}
	}
}

func (c *authConfigTree) List() []*evaluators.AuthConfig {
	var configs []*evaluators.AuthConfig
	for _, entry := range c.root.list() {
		configs = append(configs, &entry.AuthConfig)
	}
	return configs
}

func (c *authConfigTree) FindId(key string) (id string, found bool) {
	if entry := c.root.get(revertKey(key)); entry != nil {
		return entry.Id, true
	}
	return "", false
}

func (c *authConfigTree) FindKeys(id string) []string {
	return c.keys[id]
}

func newTreeNode(label string, parent *treeNode) *treeNode {
	return &treeNode{
		label:    label,
		parent:   parent,
		children: make(map[string]*treeNode),
	}
}

type treeNode struct {
	label    string
	entry    *cacheEntry
	parent   *treeNode
	children map[string]*treeNode
}

func (n *treeNode) get(key string) *cacheEntry {
	node, tail := n.longestCommonLabel(key)

	// longest common node matches the key perfectly
	if tail == "" && node.entry != nil {
		return node.entry
	}

	// lookup upwards until the root for a wildcard ('*')
	curr := node
	for {
		if child, ok := curr.children["*"]; ok && child.entry != nil {
			return child.entry
		}
		if curr.parent == nil {
			break
		}
		curr = curr.parent
	}

	return nil
}

func (n *treeNode) set(key string, entry *cacheEntry, override bool) error {
	target, tail := n.longestCommonLabel(key)

	if tail == "" {
		if !override {
			return fmt.Errorf("authconfig already exists in the cache: %s", key)
		}

		target.entry = entry
		return nil
	}

	labels := strings.Split(tail, keyLabelsSeparator)
	tld := labels[0]
	node := newTreeNode(tld, target)
	curr := node
	if len(labels) > 1 {
		for _, label := range labels[1:] {
			curr.children[label] = newTreeNode(label, curr)
			curr = curr.children[label]
		}
	}
	curr.entry = entry

	target.children[tld] = node

	return nil
}

func (n *treeNode) longestCommonLabel(key string) (node *treeNode, tail string) {
	labels := strings.Split(key, keyLabelsSeparator)

	if n.label != labels[0] {
		// We can panic here because:
		// 1) the recursion only calls while there's a common path between labels of the key and nodes of tree;
		// 2) all keys and the tree both root to `rootKeyLabel`.
		panic("cannot traverse cache tree")
	}

	if len(labels) > 1 {
		tail = strings.Join(labels[1:], keyLabelsSeparator)
		if child, ok := n.children[labels[1]]; ok {
			return child.longestCommonLabel(tail)
		}
	}

	return n, tail
}

func (n *treeNode) list() []*cacheEntry {
	var entries []*cacheEntry
	if n.entry != nil {
		entries = append(entries, n.entry)
	}
	for _, child := range n.children {
		entries = append(entries, child.list()...)
	}
	return entries
}

func revertKey(key string) string {
	labels := strings.Split(key, keyLabelsSeparator)
	labels = append(labels, rootKeyLabel)
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, keyLabelsSeparator)
}
