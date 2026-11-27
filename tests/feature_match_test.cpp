#include "feature_match.hpp"
#include <cassert>
#include <iostream>
#include <string>

int main() {
    using namespace ohno;

    // Rule syntax validation.
    assert(valid_feature_rule("minecraft"));
    assert(valid_feature_rule("orig:PlantsVsZombies.exe"));
    assert(valid_feature_rule("product:Minecraft Launcher"));
    assert(valid_feature_rule("company:Valve Corporation"));
    assert(valid_feature_rule("desc:Steam Client"));
    assert(valid_feature_rule("signer:Mojang AB"));
    assert(valid_feature_rule("title:植物大战僵尸"));
    assert(valid_feature_rule("path:steamapps"));
    assert(!valid_feature_rule(""));
    assert(!valid_feature_rule("   "));
    assert(!valid_feature_rule("product:"));
    assert(!valid_feature_rule("unknown:abc"));
    assert(!valid_feature_rule("orig:a\nb"));
    assert(!valid_feature_rule(std::string(161, 'a')));

    // Renamed game caught by PE OriginalFilename, ProductName, Company, Signer, or WindowTitle.
    ProcessFeatures renamed_pvz;
    renamed_pvz.exe_name = "notepad.exe";
    renamed_pvz.full_path = "D:\\Games\\PVZ\\notepad.exe";
    renamed_pvz.orig_filename = "PlantsVsZombies.exe";
    renamed_pvz.product_name = "Plants vs. Zombies";
    renamed_pvz.company_name = "PopCap Games";
    renamed_pvz.window_title = "植物大战僵尸中文版";

    ProcessRuleSet bl;
    bl.mode = PolicyMode::Blacklist;
    bl.block_names = {"plantsvszombies.exe"};
    assert(!should_block_process(bl, renamed_pvz, "", false)); // filename alone misses renamed game!

    bl.block_features = {"orig:plantsvszombies.exe"};
    assert(should_block_process(bl, renamed_pvz, "", false)); // PE OriginalFilename catches it!

    bl.block_features = {"company:popcap"};
    assert(should_block_process(bl, renamed_pvz, "", false));

    bl.block_features = {"title:植物大战僵尸"};
    assert(should_block_process(bl, renamed_pvz, "", false));

    // Java Minecraft running under javaw.exe caught by window title.
    ProcessFeatures java_mc;
    java_mc.exe_name = "javaw.exe";
    java_mc.product_name = "OpenJDK Platform";
    java_mc.window_title = "Minecraft* 1.20.4 - Singleplayer";
    bl.block_features = {"title:minecraft"};
    assert(should_block_process(bl, java_mc, "0123", false));
    // Temp hash grant overrides block.
    bl.temp_allowed_hashes = {"0123"};
    assert(!should_block_process(bl, java_mc, "0123", false));

    // Protected system/service processes are NEVER blocked in either mode.
    assert(!should_block_process(bl, renamed_pvz, "", true));

    // Whitelist mode: blocks unknown apps, allows whitelisted names/hashes/features/protected.
    ProcessRuleSet wl;
    wl.mode = PolicyMode::Whitelist;
    wl.allow_names = {"msedge.exe"};
    wl.allow_features = {"signer:microsoft corporation", "product:visual studio code"};
    wl.allow_hashes = {std::string(64, 'a')};

    assert(should_block_process(wl, renamed_pvz, std::string(64, 'b'), false));
    assert(should_block_process(wl, java_mc, std::string(64, 'c'), false));
    assert(!should_block_process(wl, renamed_pvz, std::string(64, 'b'), true)); // protected OS/service

    ProcessFeatures edge;
    edge.exe_name = "msedge.exe";
    assert(!should_block_process(wl, edge, std::string(64, 'd'), false));

    ProcessFeatures vscode;
    vscode.exe_name = "Code.exe";
    vscode.product_name = "Visual Studio Code";
    assert(!should_block_process(wl, vscode, std::string(64, 'e'), false));

    ProcessFeatures signed_app;
    signed_app.exe_name = "tool.exe";
    signed_app.signer = "Microsoft Corporation";
    assert(!should_block_process(wl, signed_app, std::string(64, 'f'), false));

    ProcessFeatures hash_app;
    hash_app.exe_name = "custom.exe";
    assert(!should_block_process(wl, hash_app, std::string(64, 'a'), false));

    // Temp teacher grant also permits under whitelist mode.
    wl.temp_allowed_hashes = {std::string(64, 'c')};
    assert(!should_block_process(wl, java_mc, std::string(64, 'c'), false));

    std::cout << "Feature matching and dual blacklist/whitelist policy tests passed\n";
    return 0;
}
