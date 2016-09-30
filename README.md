# iBoot64helper

## Introduction

This aims to become an IDAPython utility to help with iBoot64 reverse
engineering. Currently it just locates iBoot's proper loading address,
rebases the image, and identifies ARM64 functions based on a common
function prologue. As you can see in the screenshot below, around 790
functions are recognized after running it.

<p align="center"><img src="screenshot.png"/></p>

It's not much at this point, but hopefully it can help you start reversing
the beast ;)

I will be adding features to it, like function renaming based on string
usage, etc.

argp@census-labs.com, Fri Sep 30 13:50:29 EEST 2016

## References
[iOS RE Wiki](https://github.com/kpwn/iOSRE/blob/master/wiki/iBoot-RE.md)
