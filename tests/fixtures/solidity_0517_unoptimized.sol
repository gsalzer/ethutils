pragma solidity 0.5.17;
contract DispatchFixture {
uint256 public saved;
function() external payable {}
function f0(uint256 x) external  returns(uint256) { saved=x; return x+0; }
function f1(uint256 x) external payable returns(uint256) { saved=x; return x+1; }
function f2(uint256 x) external  returns(uint256) { saved=x; return x+2; }
function f3(uint256 x) external payable returns(uint256) { saved=x; return x+3; }
function f4(uint256 x) external  returns(uint256) { saved=x; return x+4; }
function f5(uint256 x) external payable returns(uint256) { saved=x; return x+5; }
function f6(uint256 x) external  returns(uint256) { saved=x; return x+6; }
function f7(uint256 x) external payable returns(uint256) { saved=x; return x+7; }
function f8(uint256 x) external  returns(uint256) { saved=x; return x+8; }
function f9(uint256 x) external payable returns(uint256) { saved=x; return x+9; }
function f10(uint256 x) external  returns(uint256) { saved=x; return x+10; }
function f11(uint256 x) external payable returns(uint256) { saved=x; return x+11; }
function f12(uint256 x) external  returns(uint256) { saved=x; return x+12; }
function f13(uint256 x) external payable returns(uint256) { saved=x; return x+13; }
function f14(uint256 x) external  returns(uint256) { saved=x; return x+14; }
function f15(uint256 x) external payable returns(uint256) { saved=x; return x+15; }
}
