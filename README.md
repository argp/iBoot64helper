# iBoot64helper

## Introduction

**iBoot64helper** is now an IDA loader!

Just copy *iBoot64helper.py* to your *~/.idapro/loaders/* (or your *IDA/loaders/*)
directory, launch IDA, and open a *decrypted* iBoot or iBEC (or SecureROM) binary image.

<p align="center"><img src="screenshot-loader.png"/></p>

This aims to become an IDAPython utility to help with iBoot64 reverse
engineering. Currently it a) locates iBoot's proper loading address,
b) rebases the image, c) identifies ARM64 functions based on a common
function prologue, and d) finds and renames some interesting functions.

As you can see in the screenshot below, 1920 functions
are recognized after running it on iBoot version 5540.0.129.

<p align="center"><img src="screenshot.png"/></p>

It's not much at this point, but hopefully it can help you start reversing
the beast ;)

I will be adding features to it, identifying more functions, etc.

## References
[iOS RE Wiki](https://github.com/kpwn/iOSRE/blob/master/wiki/iBoot-RE.md)
