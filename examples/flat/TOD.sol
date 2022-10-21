pragma solidity ^0.8.5;
contract TOD {
    function play_TOD(string memory guess) public {
        string memory riddle = string(abi.encode('ans_', guess));
        if (keccak256(abi.encode(riddle)) == keccak256(abi.encode('ans_hello'))) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
