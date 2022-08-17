from conans import CMake, ConanFile, tools


class OctoLoggerCPPConan(ConanFile):
    name = "octo-encryption-cpp"
    version = "1.1.0"
    url = "https://github.com/ofiriluz/octo-encryption-cpp"
    author = "Ofir Iluz"
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"

    def requirements(self):
        self.requires("catch2/3.1.0")
        self.requires("openssl/3.0.5")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        cmake.install()
        if str(self.settings.os) != "Windows":
            cmake.test()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
