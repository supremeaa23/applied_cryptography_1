// SPDX-License-Identifier: MIT

pragma solidity >=0.4.22 <0.9.0;

contract Rock_Paper_Scissors {

    address public first_player;
    address public second_player;
    enum Variant { Rock, Paper, Scissors }
    mapping(address => Variant) private variants;

    constructor() {
        first_player = msg.sender;
    }

    function joinGame() public {
        require(msg.sender != address(0));
        second_player = msg.sender;
    }

    function play(Variant variant) public {
        require(msg.sender == first_player || msg.sender == second_player);
        variants[msg.sender] = variant;
    }

    function judge() public view returns (string memory) {
        require(first_player != address(0) && second_player != address(0));
        require(variants[first_player] == Variant.Rock || variants[first_player] == Variant.Paper || variants[first_player] == Variant.Scissors);
        require(variants[second_player] == Variant.Rock  || variants[second_player] == Variant.Paper || variants[second_player] == Variant.Scissors);

        if ((variants[first_player] == Variant.Rock && variants[second_player] == Variant.Scissors) 
        || (variants[first_player] == Variant.Paper && variants[second_player] == Variant.Rock) 
        || ((variants[first_player] == Variant.Scissors && variants[second_player] == Variant.Paper))) return "Win First Player";
        if (variants[first_player] == variants[second_player]) return "Draw";
        return "Win Second Player";
    }
}
