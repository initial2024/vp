"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { publicIPv4, validRemoteName, sameSecret } = require("../bridge.js");
test("private IPv4 and metadata endpoints are blocked", () => {
  for (const ip of ["127.0.0.1", "10.2.3.4", "172.16.0.9", "192.168.0.1",
    "169.254.169.254", "100.64.0.2", "0.0.0.0", "198.18.0.1", "203.0.113.1"]) {
    assert.equal(publicIPv4(ip), false, ip);
  }
});
test("public IPv4 can pass", () => {
  assert.equal(publicIPv4("1.1.1.1"), true);
  assert.equal(publicIPv4("8.8.8.8"), true);
});
test("unsafe hostnames and IPv6 are rejected", () => {
  for (const host of ["localhost", "foo.local", "test.localhost", "127.0.0.1",
    "::1", "192.168.1.3", "a..b", ""]) {
    assert.equal(validRemoteName(host), false, host);
  }
  assert.equal(validRemoteName("example.com"), true);
});
test("authentication equality", () => {
  assert.equal(sameSecret("ASecretValue", "ASecretValue"), true);
  assert.equal(sameSecret("ASecretValue", "Another"), false);
});
