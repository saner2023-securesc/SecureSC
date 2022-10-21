/**
 * Source Code first verified at https://etherscan.io on Tuesday, May 7, 2019
 (UTC) */

pragma solidity >=0.4.22 <0.6.0;

contract HotDollarsToken {
    /*
    uint256 constant private REWARD = 2*10 - 1;
    bytes32 private GUESS = '';
    function playTOD1(bytes32 guess) external {
        GUESS = guess;
        bytes32 guess_ = guess;
        if (keccak256(abi.encode(guess_)) == keccak256(abi.encode('hello'))) {
            msg.sender.transfer(REWARD);
        }
    }
    
    bool claimedTOD2 = false;
    address payable constant OWNER = 0x03cf9d0dcCe443490a855734dE039F411250e176;
    uint256 rewardTOD2;

    function setRewardTOD2() payable external {
        require (!claimedTOD2);

        require(msg.sender == OWNER);
        rewardTOD2 = msg.value;
    }

    function claimRewardTOD2(uint256 submission) external {
        require (!claimedTOD2);
        require(submission < 10);
        msg.sender.transfer(rewardTOD2);
        claimedTOD2 = true;
    }
    */
    
    address payable winnerTOD3;
    function playTOD3(bytes32 guess) external {
       if (keccak256(abi.encode(guess)) == keccak256(abi.encode('hello'))) {
            winnerTOD3 = msg.sender;
        }
    }

    function getRewardTOD3() payable external {
        winnerTOD3.transfer(msg.value);
    }
    
}