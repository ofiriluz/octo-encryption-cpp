from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.build import check_min_cppstd
from conan.errors import ConanInvalidConfiguration
from conan.tools.scm import Version


class OctoEncryptionCPPConan(ConanFile):
    name = "octo-encryption-cpp"
    version = "1.1.0"
    url = "https://github.com/ofiriluz/octo-encryption-cpp"
    author = "Ofir Iluz"
    settings = "os", "compiler", "build_type", "arch"

    @property
    def _compilers_minimum_version(self):
        return {
            "gcc": "8",
            "clang": "9",
            "apple-clang": "11",
            "Visual Studio": "16",
        }

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()
        cd = CMakeDeps(self)
        cd.generate()

    def layout(self):
        cmake_layout(self)

    def validate(self):
        if self.info.settings.compiler.cppstd:
            check_min_cppstd(self, "17")

        minimum_version = self._compilers_minimum_version.get(str(self.info.settings.compiler), False)
        if minimum_version and Version(self.info.settings.compiler.version) < minimum_version:
            raise ConanInvalidConfiguration(
                f"{self.name} requires C++17, which your compiler does not support."
            )
        else:
            self.output.warn(f"{self.name} requires C++17. Your compiler is unknown. Assuming it supports C++17.")
        if self.settings.compiler == "clang" and self.settings.compiler.get_safe("libcxx") == "libc++":
            raise ConanInvalidConfiguration(f"{self.name} does not support clang with libc++. Use libstdc++ instead.")
        if self.settings.compiler == "Visual Studio" and self.settings.compiler.runtime in ["MTd", "MT"]:
            raise ConanInvalidConfiguration(f"{self.name} does not support MSVC MT/MTd configurations, only MD/MDd is supported")

    def requirements(self):
        self.requires("catch2/3.1.0")
        self.requires("openssl/1.1.1q")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if str(self.settings.os) != "Windows":
            cmake.test()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "octo-encryption-cpp")
        self.cpp_info.set_property("cmake_target_name", "octo::octo-encryption-cpp")
        self.cpp_info.set_property("pkg_config_name", "octo-encryption-cpp")
        self.cpp_info.components["libocto-encryption-cpp"].libs = ["octo-encryption-cpp"]
        self.cpp_info.components["libocto-encryption-cpp"].requires = ["openssl::openssl"]
        self.cpp_info.filenames["cmake_find_package"] = "octo-encryption-cpp"
        self.cpp_info.filenames["cmake_find_package_multi"] = "octo-encryption-cpp"
        self.cpp_info.names["cmake_find_package"] = "octo-encryption-cpp"
        self.cpp_info.names["cmake_find_package_multi"] = "octo-encryption-cpp"
        self.cpp_info.names["pkg_config"] = "octo-encryption-cpp"
        self.cpp_info.components["libocto-encryption-cpp"].names["cmake_find_package"] = "octo-encryption-cpp"
        self.cpp_info.components["libocto-encryption-cpp"].names["cmake_find_package_multi"] = "octo-encryption-cpp"
        self.cpp_info.components["libocto-encryption-cpp"].set_property("cmake_target_name", "octo::octo-encryption-cpp")
        self.cpp_info.components["libocto-encryption-cpp"].set_property("pkg_config_name", "octo-encryption-cpp")
