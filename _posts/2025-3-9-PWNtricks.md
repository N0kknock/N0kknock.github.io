---
title: PWN tricks
date: 2025-3-9 00:00:00 +0800
categories: [Blog, pwn]
tags: [pwn]
---

咦？这是什么？trick一下

## off by one 获取无法申请到的unsorted bin
通过off by one修改size可以进行overlap，此时进行free可以扩展堆大小，将其放入unsorted bin中

## double free泄露堆地址
如在glibc 2.26版本中，连续两次释放同一个tcache chunk，由于链中只有该chunk，导致其fd指向自己，此时show()可以泄露其fd，从而泄露堆地址

## 