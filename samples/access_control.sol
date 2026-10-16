// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccessControlVulnerable {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    function setValue(uint256 _value) external {
        value = _value;
    }

    function changeOwner(address newOwner) external {
        owner = newOwner;
    }
}