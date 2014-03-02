categolj2-cli
=============

CLI frontend for CategoLJ2

## Build

    $ go build catego.go

Show usage

     $ ./catego
      NAME:

        catego

      DESCRIPTION:

        CLI frontend for CategoLJ2

      OPTIONS:

        -cfg=<path>              File path to save config. (Default: $HOME/.categolj2cfg)
        -key=<path>              File path to save key. (Default: $HOME/.categolj2key)
        -d=<path>                File path to store downloaded entries. (Default: .) This is used only in case of GET/POST.

      COMMANDS:

        clean                    Clean files.
        rmcfg                    Remove config file.
        refreshtoken             Refresh access token.

        gets <page>              Get entries. 'page' begin with 0.
        get <filename|entryId>   Get entry.
        post <filename|entryId>  Create new entry.
        put <filename|entryId>   Update the entry.
        del <filename|entryId>   Delete the entry.
        template                 Output template entry file.

## Getting Started

### Create New Entry

`catego template` shows template file with some headers. You can write markdown (or HTML) file using this.

     $ ./catego template
    title: Title here
    category: xxx::yyy::zzz
    published: false
    updateLastModifiedDate: false
    saveInHistory: true

    ----

    Write contents here


`catego post <filename>` creates a new entry using REST API. At the first time, you have to configure blog endpoint and isses access token.

    $ ./catego template > new.md
    $ ./catego post new.md
    created /Users/maki/.categolj2cfg
    enter endpoint (ex. http://blog.ik.am): http://localhost:8080
    save /Users/maki/.categolj2cfg
    enter your secret key to encrypt: <some secret key>
    created /Users/maki/.categolj2key
    enter username: <username>
    enter password: <password>
    save /Users/maki/.categolj2cfg
    wrote ./<entryId>.md
    remove new.md

A new entry has created and downloaded as `<entryId>.md`. Original file has been deleted.

You can change directory to download with `-d <dir>`.

    $ ./catego -d foo post new.md
    create foo
    wrote foo/<entryId>.md
    remove new.md

### Get Entry/Entries

`catego get <entryId>` downloads the specified entry.

    $ ./catego get <entryId>
    download  <entryId>
    wrote ./<entryId>.md

You can change directory to download with `-d <dir>`.

    $ ./catego -d foo get 100
    download  100
    create foo
    wrote foo/100.md

`catego gets <page>` download entries by paging. `<page>` begin with 0 and default page is 0.

    $ ./catego gets
    download page 0
    wrote ./251.md
    wrote ./250.md
    wrote ./226.md
    wrote ./233.md
    wrote ./232.md
    wrote ./228.md
    wrote ./224.md
    wrote ./231.md
    wrote ./230.md
    wrote ./229.md

    $ ./catego gets 1
    download page 1
    wrote ./225.md
    wrote ./222.md
    wrote ./221.md
    wrote ./220.md
    wrote ./219.md
    wrote ./217.md
    wrote ./216.md
    wrote ./215.md
    wrote ./214.md
    wrote ./213.md

Sure, you can specify download directory.

    $ ./catego -d foo gets
    download page 0
    wrote foo/251.md
    wrote foo/250.md
    wrote foo/226.md
    wrote foo/233.md
    wrote foo/232.md
    wrote foo/228.md
    wrote foo/224.md
    wrote foo/231.md
    wrote foo/230.md
    wrote foo/229.md

### Update Entry

`catego put <filename` updates the entry.

    $ ./catego put <entryId>.md
    wrote ./<entryId>.md

You don't need to specify changed directory to download.

    $ ./catego put foo/<entryId>.md
    wrote foo/<entryId>.md

### Delete Entry

`catego del <filename>` deletes the entry.

    $ ./catego del <entryId>.md
    remove <entryId>.md

    $ ./catego del foo/<entryId>.md
    remove foo/<entryId>.md

## License

Licensed under the Apache License, Version 2.0.