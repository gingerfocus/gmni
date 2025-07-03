const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const gmni = b.createModule(.{
        .target = target,
        .optimize = optimize,
    });
    gmni.addCSourceFiles(.{
        .files = &[_][]const u8{ 
            "src/certs.c",
            "src/client.c",
            "src/escape.c",
            "src/gmni.c",
            "src/tofu.c",
            "src/url.c",
            "src/util.c",
        },
        .flags = &[_][]const u8{
            "-g",
            "-std=c11",
            "-D_XOPEN_SOURCE=700",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-Iinclude",
        },
    });
    gmni.linkSystemLibrary("bearssl", .{});
    gmni.link_libc = true;

    const exe = b.addExecutable(.{
        .name = "gmni",
        .root_module = gmni,
    });

    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("run", "Run the app");
    step.dependOn(&run.step);

    // ------------------ 

    const scdoc = b.addSystemCommand(&.{"scdoc"});
    scdoc.setStdIn(.{ .lazy_path = b.path("doc/gmni.scd") });
    const docfile = scdoc.captureStdOut();
    const docintall = b.addInstallFile(docfile, "share/man/gmni.1");

    const docs = b.step("docs", "Generate documentation");
    docs.dependOn(&docintall.step);
}
