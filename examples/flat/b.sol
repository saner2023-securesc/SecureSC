pragma solidity ^0.8.5;
contract B {
    //address[] public roles = [
    //    0x5B38Da6a701c568545dCfcB03FcB875f56beddC4,
    //    0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2];
    //function cannot_TOD3() public {
    //    require(msg.sender == roles[0], "only owner can use this method"); 
    //    payable(msg.sender).transfer(address(this).balance);
    //}
    //address private _owner;
    //function cannot_TOD1(string memory guess) public {
    //    require(msg.sender == _owner, "only owner can use this method");
    //}
    //modifier onlyOwner {
    //    require(msg.sender == _owner, "only owner can use this method");
    //    _;
    //}
    //function cannot_TOD2() public {
    //    payable(msg.sender).transfer(address(this).balance);
    //}
    function _verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) private view returns(bool) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHash = keccak256(abi.encodePacked(prefix, hash));
        address recovered = ecrecover(prefixedHash, v, r, s);
    }
}
