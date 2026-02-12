#pragma once

#include "mesh_message.hpp"
#include <chrono>
#include <deque>
#include <functional>
#include <mutex>
#include <unordered_map>

namespace vpn::mesh {

// Entry in a k-bucket
struct KBucketEntry {
    NodeId node_id;
    NodeInfo info;
    std::chrono::steady_clock::time_point last_seen;
    bool is_stale = false;
};

// Single k-bucket holding up to K_BUCKET_SIZE entries
class KBucket {
public:
    // Add or update a node. Returns true if added/updated, false if bucket full
    // and head node is responsive (caller should ping head first).
    bool add_or_update(const KBucketEntry& entry);

    // Remove a node by ID
    void remove(const NodeId& node_id);

    // Mark head as stale (after failed ping) and replace with pending
    void evict_head(const NodeId& replacement_id, const NodeInfo& replacement_info);

    // Get all entries
    const std::deque<KBucketEntry>& entries() const { return entries_; }

    // Check if bucket is full
    bool is_full() const { return entries_.size() >= K_BUCKET_SIZE; }

    // Check if empty
    bool is_empty() const { return entries_.empty(); }

    // Get the head entry (least recently seen)
    const KBucketEntry* head() const;

    // Get last activity time
    std::chrono::steady_clock::time_point last_updated() const { return last_updated_; }

    // Check if bucket needs refresh
    bool needs_refresh(std::chrono::minutes interval = std::chrono::minutes(15)) const;

    // Find an entry by ID
    const KBucketEntry* find(const NodeId& node_id) const;

    // Number of entries
    size_t size() const { return entries_.size(); }

private:
    std::deque<KBucketEntry> entries_;
    std::chrono::steady_clock::time_point last_updated_ = std::chrono::steady_clock::now();
};

// Kademlia routing table with 160 k-buckets
class RoutingTable {
public:
    explicit RoutingTable(const NodeId& local_id);

    // Add or update a node in the routing table
    bool add_or_update(const NodeInfo& info);

    // Remove a node
    void remove(const NodeId& node_id);

    // Find the k closest nodes to a target
    std::vector<NodeInfo> find_closest(const NodeId& target, size_t count = K_BUCKET_SIZE) const;

    // Get the bucket index for a given node ID
    int bucket_index(const NodeId& node_id) const;

    // Get a specific bucket
    const KBucket& bucket(int index) const { return buckets_[index]; }
    KBucket& bucket(int index) { return buckets_[index]; }

    // Get all nodes
    std::vector<NodeInfo> all_nodes() const;

    // Get total node count
    size_t node_count() const;

    // Get local ID
    const NodeId& local_id() const { return local_id_; }

    // Find buckets that need refresh
    std::vector<int> stale_buckets(std::chrono::minutes interval = std::chrono::minutes(15)) const;

    // Generate a random node ID in the range of a specific bucket
    static NodeId random_id_in_bucket(const NodeId& local_id, int bucket_index);

private:
    NodeId local_id_;
    std::array<KBucket, NODE_ID_BITS> buckets_;
};

// Key-value store with TTL expiry for Kademlia STORE/FIND_VALUE
class DhtStore {
public:
    struct StoreEntry {
        std::vector<uint8_t> value;
        std::chrono::steady_clock::time_point expires_at;
        NodeId publisher_id;
    };

    // Store a value with TTL
    void store(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value,
               const NodeId& publisher, uint32_t ttl_seconds = 3600);

    // Find a value by key
    std::optional<std::vector<uint8_t>> find(const std::vector<uint8_t>& key) const;

    // Remove expired entries
    void expire();

    // Get all entries (for republishing)
    std::vector<std::pair<std::vector<uint8_t>, StoreEntry>> all_entries() const;

    // Size
    size_t size() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, StoreEntry> store_;

    static std::string key_to_string(const std::vector<uint8_t>& key);
};

// State machine for iterative parallel Kademlia lookups
class IterativeLookup {
public:
    enum class State {
        Running,
        Converged,
        Failed
    };

    // Callback to send a FIND_NODE message and get response
    using SendCallback = std::function<void(const NodeInfo& target, const NodeId& lookup_target)>;

    IterativeLookup(const NodeId& target, const std::vector<NodeInfo>& initial_nodes,
                    size_t k = K_BUCKET_SIZE, size_t alpha = ALPHA);

    // Get next batch of nodes to query (up to alpha)
    std::vector<NodeInfo> next_to_query();

    // Process response from a queried node
    void process_response(const NodeId& responder, const std::vector<NodeInfo>& closer_nodes);

    // Mark a query as failed (timeout, etc.)
    void mark_failed(const NodeId& node_id);

    // Get current state
    State state() const { return state_; }

    // Get the k closest nodes found so far
    std::vector<NodeInfo> closest_results() const;

    // Get the target ID
    const NodeId& target() const { return target_; }

private:
    struct LookupEntry {
        NodeInfo info;
        NodeId distance;
        bool queried = false;
        bool responded = false;
        bool failed = false;
    };

    void update_state();

    NodeId target_;
    size_t k_;
    size_t alpha_;
    State state_ = State::Running;

    std::vector<LookupEntry> entries_;
    size_t pending_queries_ = 0;
};

} // namespace vpn::mesh
