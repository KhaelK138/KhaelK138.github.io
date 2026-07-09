---
layout: blog
title: 2-Click Remote Code Execution in Meccha Chameleon
description: Achieving remote code execution on every player in a game lobby through a malicious Steam Workshop map.
author: Khael Kugler
date: June 21, 2026
---

![Meccha Chameleon gameplay with a command prompt and calculator spawned by the exploit](./images/meccha_chameleon/meccha_title.png)

## Introduction

[MECCHA CHAMELEON](https://store.steampowered.com/app/4704690/MECCHA_CHAMELEON/), a hide-and-seek game on Steam built with Unreal Engine 5, has been quite the rage recently. An indie game developer's dream: 7 million downloads (as of writing) without a single cent spent on advertising, and for good reason. It's a take on the classic prop hunt game, where players attempt to hide in a cluttered map from hunters, but with the added twist of being able to *literally* paint themselves into the scenery. For example, can you spot me below? I've added an arrow to help.

![Farm map in Meccha Chameleon with an arrow pointing to a camouflaged player on the barn](./images/meccha_chameleon/hidden_player.png)

However, these types of indie games often sport rich attack surfaces, as we'll examine. 

## Custom Maps

One of the best parts of the game is the built-in support for custom maps. Without modding the game, players can create maps in UE5, package them into `.pak` files, and upload them to Steam's official Workshop for others to play. 

![Steam Workshop page showing popular custom maps for Meccha Chameleon](./images/meccha_chameleon/workshop_maps.png)

When a lobby host selects a custom map, all players are prompted to download the map from Steam before the game can start. The gameplay loop itself reinforces this; nobody wants to be the one holding up the lobby.

![Victim prompted to download the Workshop map](./images/meccha_chameleon/victim_download_prompt.png)

Crucially, Workshop maps can contain more than just levels and textures. They can also include [Blueprint](https://dev.epicgames.com/documentation/unreal-engine/blueprints-visual-scripting-in-unreal-engine) logic, which is UE5's visual scripting system. Any Blueprint placed in a map has its `BeginPlay` event fire automatically when the map loads on a client. This is standard behavior, used for things like animated doors or environmental effects, but it also means that any logic the map creator includes will execute on every player's machine upon being loaded. But what can actually be included in this logic?

## Digging into Blueprint Scripting & LaunchURL

Many of the functions available were pretty boring from a security perspective. Lighting changes, visual effects, debug info, and so on. Surprisingly, Python commands were available, but they were restricted to the development environment and wouldn't execute in a deployed map.

One node did stand out, though: `LaunchURL`. At first glance, it seemed somewhat harmless--a function for opening URLs in the user's default browser. You could imagine a map creator using it to link to their social media or a Discord server.

![UE5 Blueprint with BeginPlay event connected to a LaunchURL node opening a website](./images/meccha_chameleon/launchurl_example.png)

To understand what it actually did under the hood, I pulled the game's shipping binary (`PenguinHotel-Win64-Shipping.exe`) into Ghidra. The Blueprint-callable entry point, `UKismetSystemLibrary::execLaunchURL`, lives at `0x143e305e0`. Following the call chain, it goes through `LaunchURLFiltered`, `LaunchURL`, and eventually lands on `FWindowsPlatformProcess::LaunchURLInternal`, which calls `ShellExecuteW(NULL, "open", URL, NULL, NULL, SW_SHOWNORMAL)`.

![Ghidra decompilation showing the LaunchURL call chain](./images/meccha_chameleon/launchurl_ghidra.png)

This immediately became a lot more interesting. `ShellExecuteW` with the `"open"` verb isn't just for web pages. It tells Windows to *launch* the path - similar to double-clicking a file - including running executables.

However, as some of you may have noticed, we don't have argument control over the `ShellExecuteW` call - `lpParameters` is always NULL:

```
pHVar6 = ShellExecuteW((HWND)0x0,L"open",param_1,(LPCWSTR)0x0,(LPCWSTR)0x0,1)
```

This means something like `"cmd.exe", "/c whoami"` is off the table, and passing `"cmd.exe /c whoami"` would attempt to open the entire string as a path. Running arbitrary commands requires somehow providing a malicious file to the `LaunchURL` command. 

The natural next thought is a UNC path--host a batch file on an attacker-controlled SMB share and pass `\\attacker\share\payload.bat`. Unfortunately, `LaunchURLInternal` only routes valid, non-HTTP/HTTPS schemes (like `file://` or `steam://`) to `ShellExecuteW`. UNC paths don't have a scheme, so they were routed to `LaunchWebURL` and opened in the browser. 

Thus, the question became: how do you plant a file on the victim's machine, at a path you know in advance?

## Arbitrary File Delivery

Lucky for me, Steam Workshop items (such as maps) are essentially just folders. When a player uploads content, Steam intentionally allows every file type to be uploaded, leaving it up to the developer to restrict what files are mounted. [Their documentation even calls this out](https://partner.steamgames.com/doc/features/workshop#:~:text=your%20submission%20tool%20should), noting to developers that "your submission tool should accept *just* the file formats your game client expects to load." 

![Example Map folder, including an unexpected executable.](./images/meccha_chameleon/workshop_map.png)

Upon testing, Meccha Chameleon enforced no restrictions on uploaded file types. So let's just toss a file in the map folder itself, and `LaunchURL` that path!

To pull this off, I needed a Workshop item ID first. Steam downloads Workshop content to a predictable path on every subscriber's machine - `C:\Program Files (x86)\Steam\steamapps\workshop\content\<app_id>\<workshop_id>\` - but you don't get an item ID until you've uploaded something. So the first step was uploading a benign map just to claim one.

After following many, many tutorials, I created a test map in UE5 and uploaded it.

![UE5 editor with test map and Blueprint Actor](./images/meccha_chameleon/ue5_test_map.png)

![Initial Workshop upload via Steam command line](./images/meccha_chameleon/vdf_initial_upload.png)

Steam assigned it ID `3747657449`. Combined with the game's AppID (`4704690`), this meant most subscribers would download the map's files to `C:\Program Files (x86)\Steam\steamapps\workshop\content\4704690\3747657449\`.

With the path known, I created `payload.bat` (simply running `whoami`) and dropped it in the upload folder next to the map's `.pak`, `.ucas`, and `.utoc` files. 

![payload.bat alongside map files in the upload directory](./images/meccha_chameleon/payload_bat.png)

I updated the Blueprint's `BeginPlay` event to call `LaunchURL` with the full path to the batch file and reuploaded the map.

![Blueprint event graph with LaunchURL pointing to payload.bat and the file:// scheme](./images/meccha_chameleon/blueprint_launchurl.png)
![Reuploading the malicious map](./images/meccha_chameleon/vdf_reupload.png)

Time to test it out!

## Confirming Execution

As the attacker, I started by hosting a lobby and selecting the custom map in the lobby settings.

![Attacker selecting the malicious map as lobby host](./images/meccha_chameleon/host_select_map.png)

I joined the lobby with a second account and started the game as the host. My victim player in the lobby got the usual prompt to download the map. Clicking through took them to the Steam Workshop page, prompting them to subscribe.

![In-game prompt telling the player to download the custom map](./images/meccha_chameleon/victim_download_prompt2.png)
![Map page shown to victim in Steam overlay](./images/meccha_chameleon/victim_steam_page.png)

As soon as I clicked `Subscribe`, the map downloaded, `BeginPlay` fired, and `payload.bat` executed. A command prompt popped up with the output of `whoami`.

![whoami executing on the victim's machine after subscribing](./images/meccha_chameleon/rce_whoami.png)

Two clicks, and the attacker has arbitrary command execution on the victim's machine. The batch file could just as easily be a reverse shell, a malware dropper, or anything else. 

It's also worth noting that these custom maps are extremely popular. As of writing, the custom "Minecraft" Workshop map had an astounding 2 million subscriptions, out of a total 7 million game downloads, with many others also in the millions or hundreds of thousands. This feature is a very commonly used and accepted part of the game; players don't think twice about installing items from the Workshop. A well-crafted (or purchased) map could easily amass a massive player base. Worse yet, Steam Workshop items auto-update. A trusted, established map could silently deliver a payload to its entire subscriber base overnight.

## Takeaways

This sort of attack seems to be somewhat prevalent within these types of games. Malicious Workshop content has been seen before, such as [Kaspersky's discovery of malicious Wallpaper Engine uploads](https://www.kaspersky.com/about/press-releases/kaspersky-discovered-a-malware-campaign-targeting-steam-users-through-infected-wallpaper). It's tough for developers to recognize what constitutes attacker-controlled data, and it's easy to assume that Steam handles the filtering. If your game supports user-generated content, treat it as untrusted code--allowlist asset file types in Workshop uploads and restrict UE5 Blueprint usage. 

This vulnerability has been patched in the latest versions, with the game no longer mounting arbitrary files to disk and only accepting files with whitelisted extensions. I've also reached out to Epic Games to hopefully establish a default policy in UE5 that prevents Blueprint `LaunchURL` calls from launching anything other than safe HTTP/HTTPS links, though I've yet to hear back. If game developers would like maps to be able to launch other schemes, they would ideally have to manually add them to an allowlist. Secure defaults, folks!