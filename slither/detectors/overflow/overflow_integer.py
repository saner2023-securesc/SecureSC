from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
# from slither.slithir.operations.assignment import Assignment
from slither.slithir.operations.binary import Binary, BinaryType
from slither.analyses.data_dependency.data_dependency import *

class OverflowInteger(AbstractDetector):
    """
    Detect function named overflow
    """

    ARGUMENT = 'overflow-integer'  # slither will launch the detector with slither xxx.sol --detect overflow
    HELP = 'Function named overflow (my detector)'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM


    WIKI = 'https://github.com/trailofbits/slither/wiki/NA'
    WIKI_TITLE = 'Overflow self-define'
    WIKI_DESCRIPTION = 'Overflow self-define'
    WIKI_EXPLOIT_SCENARIO = '..'
    WIKI_RECOMMENDATION = '..'

    def _detect(self):
        results = []

        for contract in self.slither.contracts:
            for f in contract.functions:
                for n in f.nodes:              
                    # to detect something like x = y + z
                    flag = False  #flag==False -> There is no overflow
                    for ir in n.irs:     
                        if isinstance(ir, Binary) and (is_tainted(ir.variable_left,f) or is_tainted(ir.variable_right,f)):
                            lv = ir.variable_left
                            rv = ir.variable_right
                            maxLV = self._maxsize(lv)
                            maxRV = self._maxsize(rv)
                            minLV = self._minsize(lv)
                            minRV = self._minsize(rv)
                            maxAcceptable = self._maxsize(ir.lvalue)
                            minAcceptable = self._minsize(ir.lvalue)
                            if ir.type == BinaryType.ADDITION:
                                flag = maxAcceptable < maxLV + maxRV
                            elif ir.type == BinaryType.MULTIPLICATION:
                                flag = maxAcceptable < maxLV * maxRV or minAcceptable > minLV * maxRV or minAcceptable > maxLV * minRV
                            elif ir.type == BinaryType.SUBTRACTION:
                                flag = maxAcceptable < maxLV - minRV or minAcceptable > minLV - maxRV
                            elif ir.type == BinaryType.POWER:
                                flag = maxAcceptable < maxLV**maxRV or minAcceptable > minLV**maxRV
                    if flag == True:   #flag==True -> overflow
                        info = ['Overflow function found in ', n,'\n']
                        res = self.generate_result(info)
                        results.append(res)
        return results
        
    def _maxsize(self, instance) :
        str = instance.type.type
        if str == 'uint':   #uint (uint256)
            return 2**256-1
        elif str == 'int':  #int (int256)
            return 2**255-1
        elif str.startswith('uint'):    #uint8/16/...
            length = int(str[4:])
            return 2**length-1
        elif str.startswith('int'):     #int8/16/...
            length = int(str[4:])-1
            return 2**length-1
        else:
            return None

    def _minsize(self, instance) :
        str = instance.type.type
        if str == 'int':    #int (int256)
            return -2**255+1
        elif str.startswith('uint'):    #uint8/16/...
            return 0
        elif str.startswith('int'):     #/int8/16...
            length = int(str[4:])-1
            return -2**length+1
        else:
            return None