from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout


class VpnServerConan(ConanFile):
    name = "vpn-server"
    version = "1.0.0"
    description = "WireGuard-compatible VPN server with mesh networking"
    license = "Proprietary"
    url = "https://github.com/scorpiondefense/vpn_server"
    settings = "os", "compiler", "build_type", "arch"
    exports_sources = (
        "CMakeLists.txt",
        "src/*",
        "include/*",
        "tools/*",
        "tests/*",
    )

    # Dependencies are system-installed (libsodium via pkg-config)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["vpn_lib"]
        self.cpp_info.set_property("cmake_file_name", "vpn_server")
        self.cpp_info.set_property("cmake_target_name", "vpn::vpn_lib")
        self.cpp_info.system_libs = ["sodium"]
        if self.settings.os == "Linux":
            self.cpp_info.system_libs.append("pthread")
