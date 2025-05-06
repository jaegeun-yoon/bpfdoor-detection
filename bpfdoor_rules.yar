import "hash"

rule BPFdoor_Backdoor {
    meta:
        author = "jaegeun.yoon"
        description = "Detects known BPFdoor-related files by filename, size, and SHA256 hash"
        reference = "Custom detection based on known hashes"

    condition:
        // dbus-srv
        (filesize == 34KB and (hash.sha256(0, filesize) == "925ec4e617adc81d6fcee60876f6b878e0313a11f25526179716a90c3b743173")) or

        // inode262394
        (filesize == 28KB and (hash.sha256(0, filesize) == "29564c19a15b06dd5be2a73d7543288f5b4e9e6668bbd5e48d3093fb6ddf1fdb")) or

        // dbus-srv
        (filesize == 34KB and (hash.sha256(0, filesize) == "be7d952d37812b7482c1d770433a499372fde7254981ce2e8e974a67f6a088b5")) or

        // dbus-srv
        (filesize == 34KB and (hash.sha256(0, filesize) == "027b1fed1b8213b86d8faebf51879ccc9b1afec7176e31354fbac695e8daf416")) or

        // dbus-srv
        (filesize == 32KB and (hash.sha256(0, filesize) == "a2ea82b3f5be30916c4a00a7759aa6ec1ae6ddadc4d82b3481640d8f6a325d59")) or

        // File_in_Inode_#1900667
        (filesize == 28KB and (hash.sha256(0, filesize) == "e04586672874685b019e9120fcd1509d68af6f9bc513e739575fc73edefd511d")) or

        // gm
        (filesize == 2063KB and (hash.sha256(0, filesize) == "adfdd11d69f4e971c87ca5b2073682d90118c0b3a3a9f5fbbda872ab1fb335c6")) or

        // rad
        (filesize == 22KB and (hash.sha256(0, filesize) == "7c39f3c3120e35b8ab89181f191f01e2556ca558475a2803cb1f02c05c830423")) or

        // hpasmmld
        (filesize == 2320640 and hash.sha256(0, filesize) == "c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4") or

        // smartadm
        (filesize == 2116608 and hash.sha256(0, filesize) == "3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4") or

        // hald-addon-volume
        (filesize == 2120704 and hash.sha256(0, filesize) == "95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595") or

        // dbus-srv-bin.txt
        (filesize == 34816   and hash.sha256(0, filesize) == "aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4")

}
