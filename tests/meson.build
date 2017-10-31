# Each test must follow the convention: check-$name.c, i.e. "check-os-release.c"
desired_tests = [
    'cmdline',
    'core',
    'grub2',
    'legacy',
    'os-release',
    'probe',
    'select-bootloader',
    'uefi',
]

test_dependencies = [
    link_libcbm,
    libcbm_dependencies,
    dep_check,
]

# Shared sources between each test run
libtest_sources = [
    'harness.c',
]

# Create a new executable for every given test in desired_tests
foreach test_name : desired_tests
    tmp_exec = executable(
        'test-@0@'.format(test_name),
        sources: [
            'check-@0@.c'.format(test_name),
        ] + libtest_sources,
        dependencies: [
            test_dependencies,
        ],
        c_args: [
            '-DTOP_BUILD_DIR="@0@/root/test-root-@1@"'.format(meson.current_build_dir(), test_name),
            '-DTOP_DIR="@0@"'.format(test_top_dir),
        ],
        install: false,
    )
    test(test_name, tmp_exec)
endforeach
