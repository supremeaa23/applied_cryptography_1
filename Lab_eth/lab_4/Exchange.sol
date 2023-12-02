// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract Exchange {
    IERC20 public A;
    IERC20 public B;
    address public owner;

    constructor(IERC20 _tokenA, IERC20 _tokenB) {
        A = _tokenA;
        B = _tokenB;
        owner = msg.sender;
    }

    function exchangeAToB(uint amountA) external {
        require(A.transferFrom(msg.sender, address(this), amountA), "Failed");
        uint amountB = amountA;
        require(B.transfer(msg.sender, amountB), "Failed");
    }

    function exchangeBToA(uint amountB) external {
        require(B.transferFrom(msg.sender, address(this), amountB), "Failed");
        uint amountA = amountB;
        require(A.transfer(msg.sender, amountA), "Failed");
    }
}
