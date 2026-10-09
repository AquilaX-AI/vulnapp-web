package main

// decoyFiles backs the "fake" path traversal demo on /files.
//
// The handler never touches the real filesystem for traversal payloads: it
// only matches the requested base filename (case-insensitively) against this
// map and serves canned content. This lets a DAST scanner's traversal
// payloads (../../../etc/passwd, ..\..\windows\win.ini, URL-encoded
// variants, etc.) at any depth "succeed" against a realistic-looking
// fingerprint, without ever reading a real system file.
var decoyFiles = map[string]string{
	"passwd": `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
vulnapp:x:1000:1000:vulnapp,,,:/home/vulnapp:/bin/bash
`,
	"shadow": `root:$6$fakeSaltValue$3dlUO9Jk1h5s8k2m9bFakeHashOnlyNotReal0000000000000000000000:19700:0:99999:7:::
vulnapp:$6$fakeSaltValue$9zQp1xFakeHashDemoDataOnly000000000000000000000000000000000:19700:0:99999:7:::
`,
	"win.ini": `; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
`,
	"boot.ini": `[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect
`,
	"id_rsa": `-----BEGIN OPENSSH PRIVATE KEY-----
FAKEKEYDATAFAKEKEYDATAFAKEKEYDATAFAKEKEYDATAFAKEKEYDATAFAKEKEY
THISISNOTAREALPRIVATEKEYITISADECOYFORVULNAPPWEBPATHTRAVERSAL==
-----END OPENSSH PRIVATE KEY-----
`,
}
