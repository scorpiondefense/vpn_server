#include <catch2/catch_test_macros.hpp>
#include "vpn/mesh/mesh_config.hpp"

using namespace vpn::mesh;

TEST_CASE("has_mesh_section detection", "[mesh][config]") {
    REQUIRE(has_mesh_section("[Mesh]\nNetworkName = test"));
    REQUIRE(has_mesh_section("[Interface]\n[mesh]\n"));
    REQUIRE_FALSE(has_mesh_section("[Interface]\n[Peer]\n"));
    REQUIRE_FALSE(has_mesh_section(""));
}

TEST_CASE("has_beacon_section detection", "[mesh][config]") {
    REQUIRE(has_beacon_section("[Beacon]\nNetworkName = test"));
    REQUIRE(has_beacon_section("[Interface]\n[beacon]\n"));
    REQUIRE_FALSE(has_beacon_section("[Interface]\n[Mesh]\n"));
    REQUIRE_FALSE(has_beacon_section(""));
}

TEST_CASE("MeshConfigFile parse", "[mesh][config]") {
    std::string config = R"(
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
Address = 10.100.0.1/16

[Mesh]
NetworkName = test-network
NetworkSecret = aGVsbG93b3JsZA==
BeaconAddress = 1.2.3.4:51821
BeaconPublicKey = HIgo9xNzJMWLKASShiTqIybxR0V1HRjF/T1VEVS+vCY=
AutoConnect = true
MaxPeers = 50
IPv6Address = fd00:mesh::1/64
)";

    auto parsed = MeshConfigFile::parse(config);
    REQUIRE(parsed.has_value());

    CHECK(parsed->private_key_base64 == "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
    CHECK(parsed->listen_port == 51820);
    CHECK(parsed->address == "10.100.0.1/16");

    CHECK(parsed->mesh.network_name == "test-network");
    CHECK(parsed->mesh.network_secret_base64 == "aGVsbG93b3JsZA==");
    CHECK(parsed->mesh.beacon_address == "1.2.3.4:51821");
    CHECK(parsed->mesh.beacon_public_key_base64 == "HIgo9xNzJMWLKASShiTqIybxR0V1HRjF/T1VEVS+vCY=");
    CHECK(parsed->mesh.auto_connect == true);
    CHECK(parsed->mesh.max_peers == 50);
    CHECK(parsed->mesh.ipv6_address == "fd00:mesh::1/64");
}

TEST_CASE("MeshConfigFile validate", "[mesh][config]") {
    SECTION("Valid config") {
        std::string config = R"(
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
Address = 10.100.0.1/16

[Mesh]
NetworkName = test
NetworkSecret = aGVsbG93b3JsZA==
BeaconAddress = 1.2.3.4:51821
BeaconPublicKey = HIgo9xNzJMWLKASShiTqIybxR0V1HRjF/T1VEVS+vCY=
)";
        auto parsed = MeshConfigFile::parse(config);
        REQUIRE(parsed.has_value());
        REQUIRE(parsed->validate());
    }

    SECTION("Missing private key") {
        std::string config = R"(
[Interface]
ListenPort = 51820
Address = 10.100.0.1/16

[Mesh]
NetworkName = test
NetworkSecret = aGVsbG93b3JsZA==
BeaconAddress = 1.2.3.4:51821
BeaconPublicKey = HIgo9xNzJMWLKASShiTqIybxR0V1HRjF/T1VEVS+vCY=
)";
        auto parsed = MeshConfigFile::parse(config);
        REQUIRE(parsed.has_value());
        REQUIRE_FALSE(parsed->validate());
    }

    SECTION("Missing network name") {
        std::string config = R"(
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
Address = 10.100.0.1/16

[Mesh]
NetworkSecret = aGVsbG93b3JsZA==
BeaconAddress = 1.2.3.4:51821
BeaconPublicKey = HIgo9xNzJMWLKASShiTqIybxR0V1HRjF/T1VEVS+vCY=
)";
        auto parsed = MeshConfigFile::parse(config);
        REQUIRE(parsed.has_value());
        REQUIRE_FALSE(parsed->validate());
    }
}

TEST_CASE("BeaconConfigFile parse", "[mesh][config]") {
    std::string config = R"(
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51821

[Beacon]
NetworkName = scorpion-corp
NetworkSecret = aGVsbG93b3JsZA==
MaxPeers = 500
PeerExpiry = 600
)";

    auto parsed = BeaconConfigFile::parse(config);
    REQUIRE(parsed.has_value());

    CHECK(parsed->private_key_base64 == "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
    CHECK(parsed->listen_port == 51821);
    CHECK(parsed->network_name == "scorpion-corp");
    CHECK(parsed->network_secret_base64 == "aGVsbG93b3JsZA==");
    CHECK(parsed->max_peers == 500);
    CHECK(parsed->peer_expiry_seconds == 600);
}

TEST_CASE("BeaconConfigFile validate", "[mesh][config]") {
    SECTION("Valid config") {
        std::string config = R"(
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51821

[Beacon]
NetworkName = test
NetworkSecret = aGVsbG93b3JsZA==
)";
        auto parsed = BeaconConfigFile::parse(config);
        REQUIRE(parsed.has_value());
        REQUIRE(parsed->validate());
    }

    SECTION("Missing network name") {
        std::string config = R"(
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

[Beacon]
NetworkSecret = aGVsbG93b3JsZA==
)";
        auto parsed = BeaconConfigFile::parse(config);
        REQUIRE(parsed.has_value());
        REQUIRE_FALSE(parsed->validate());
    }
}

TEST_CASE("MeshConfigFile generate_sample", "[mesh][config]") {
    auto sample = MeshConfigFile::generate_sample();
    REQUIRE(!sample.empty());
    REQUIRE(has_mesh_section(sample));
}

TEST_CASE("BeaconConfigFile generate_sample", "[mesh][config]") {
    auto sample = BeaconConfigFile::generate_sample();
    REQUIRE(!sample.empty());
    REQUIRE(has_beacon_section(sample));
}
