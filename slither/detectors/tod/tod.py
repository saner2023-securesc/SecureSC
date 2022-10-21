from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.analyses.data_dependency.data_dependency import (
    is_dependent,
    is_dependent_ssa,
    get_dependencies,
    get_dependencies_ssa
)
from slither.core.cfg.node import NodeType
from slither.core.declarations import Function
from slither.core.declarations.function_top_level import FunctionTopLevel
from slither.core.solidity_types import MappingType, ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations.solidity_variables import (
    SolidityVariable,
    SolidityVariableComposed,
    SolidityFunction,
)
from slither.slithir.operations import (
    Index,
    Assignment,
    Binary,
    BinaryType,
    HighLevelCall,
    SolidityCall,
)
from slither.slithir.variables import (
    Constant,
    TemporaryVariable,
    ReferenceVariable
)

class TOD(AbstractDetector):
    """
    Detect function named TOD
    """

    ARGUMENT = "TOD"  # slither will launch the detector with slither.py --mydetector
    HELP = "Transaction Ordering Dependency"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = ".."
    WIKI_TITLE = ".."
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    sources_taint = [
        SolidityVariable("now"),
        SolidityVariableComposed("block.number"),
        SolidityVariableComposed("block.timestamp"),
    ]

    state_var = []
    global_taint_nodes = []
    access_control_state_var = []

    @staticmethod
    def is_direct_comparison(ir):
        return isinstance(ir, Binary) and ir.type == BinaryType.EQUAL

    @staticmethod
    def is_any_tainted(variables, taints, function) -> bool:
        return any(
            (
                is_dependent(var, taint, function.contract)
                for var in variables
                for taint in taints
            )
        )

    @staticmethod
    def is_any_tainted_ssa(variables, taints, function) -> bool:
        return any(
            (
                is_dependent_ssa(var, taint, function.contract)
                for var in variables
                for taint in taints
            )
        )

    # Retrieve all tainted (node, function) pairs
    # TODO: func modifier
    def tainted_nodes(self, func, taints):
        sink = []
        taint_nodes = []
        taints += self.sources_taint

        # Disable the detector on top level function until we have good taint on those
        if isinstance(func, FunctionTopLevel) or self.is_access_control(func):
            return taint_nodes
        for node in func.nodes:
            # print(node, self.is_sensitive_operation(node))
            # case Init Node:

            # case Assignment Node: Explicit-taint-analysis (Data Dependency)
            if node.type in [NodeType.EXPRESSION, NodeType.VARIABLE] and not node.contains_require_or_assert() and not self.is_sensitive_operation(node): # msg.sender.transfer(REWARD) is also EXPRESSION
                for ir in node.irs:             # node.irs_ssa
                    # Filter to only tainted
                    for var in ir.used:
                        if self.is_any_tainted([var], taints, func):
                            if not any([
                                var.name == v.name
                                for v in taints
                            ]):
                                taints.append(var)
                        # state data dependency
                        if var in self.state_var and node in taint_nodes:
                            if not any([
                                var.name == v.name
                                for v in self.global_taint_nodes
                            ]):
                                self.global_taint_nodes.append(var)

            # case IF / IF_LOOP / BEGIN_LOOP: Implicit-taint-analysis (Control Dependency)
            elif node.type in [NodeType.IF, NodeType.IFLOOP]:
                for ir in node.irs:             # node.irs_ssa
                    for var in ir.used:
                        if self.is_any_tainted([var], taints, func):
                            taint_node = self.control_dependency(node, func)
                            taint_nodes = list(set(taint_node+taint_nodes))
                            # if node not in taint_nodes:
                            #     taint_nodes.append(node)
            
            # case require / assert, like require(a > b OR c is in d): Decontamination
            elif node.type in [NodeType.EXPRESSION, NodeType.VARIABLE] and node.contains_require_or_assert():
                for ir in node.irs:             # node.irs_ssa
                    for var in ir.used:
                        if self.is_any_tainted([var], taints, func):
                            taint_node = self.control_dependency(node, func)
                            taint_nodes = list(set(taint_node+taint_nodes))
                            # if node not in taint_nodes:
                            #     taint_nodes.append(node)

            # case Transfer / Selfdestruct / transferFrom(address,address,uint256): sink
            elif self.is_sensitive_operation(node):
                if node in taint_nodes or self.state_dependency_with_taint_nodes(node):
                    sink.append(node)
                
        return sink

    def is_access_control(self, f) -> bool:
        # The onlyOwner modifier prevents calling the contract
        exclusive = list(filter(lambda x:str(x.type)=='address', self.access_control_state_var))
        for modifier in f.modifiers:
            if self.is_access_control(modifier):
                return True
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, Index): # roles[0]
                    tmp = isinstance(ir.variable_right, Constant)
                    if tmp:
                        exclusive.append(ir._lvalue)
                elif isinstance(ir, SolidityCall): # ecrecover, merkle
                    tmp = ir.function.full_name
                    if any(name in tmp for name in ['ecrecover', 'merkle', 'Merkle']):
                        exclusive.append(ir._lvalue)
                elif isinstance(ir, BinaryType): # ecrecover, merkle
                    for var in ir.used: # msg.sender
                        if var.name == 'msg.sender':            
                            ir.used.remove(var)
                            for v in ir.used:
                                if any([
                                        v.name == ex.name and v.name != 'msg.sender'
                                        for ex in exclusive
                                    ]):
                                    return True
        return {"onlyOwner", "onlyManager"}&{modifier.name for modifier in f.modifiers}

    def control_dependency(self, node, func):
        res = []
        nodes = func.nodes
        node_index = nodes.index(node)
        for i in range(node_index+1, len(nodes)):
            node = nodes[i]
            if node.contains_require_or_assert() or node.type in [NodeType.IF, NodeType.IFLOOP, NodeType.ENDIF, NodeType.ENDLOOP, NodeType.STARTLOOP, NodeType.BREAK, NodeType.THROW]:
                return res
            res.append(node)
        return res
    
    def is_sensitive_operation(self, node):
        is_send_eth = node.can_send_eth()
        is_suicidal = any(
            c.name in ["suicide(address)", "selfdestruct(address)"]
            for c in node.internal_calls
        )
        return is_send_eth or is_suicidal
        # return any(
        #     c.name in ["require(bool)", "require(bool,string)", "assert(bool)"]
        #     for c in node.internal_calls
        # )

    def detect_tod(self, func, tainted_state):
        
        # Taint Source
        # parameter
        tainted_param = func.parameters_ssa         # func.parameters or func.parameters_ssa
        tainted_param = func.parameters
        taints = tainted_state + tainted_param
        
        # Accumulate tainted (node,function) pairs involved in strict equality (==) comparisons
        results = self.tainted_nodes(func, taints)
        return results

    def state_dependency_with_taint_nodes(self, node):
        for ir in node.irs:             # node.irs_ssa
            for var in ir.used:
                if var in self.global_taint_nodes:
                    return True
        return False

    def get_state(self, contract):
        """
        Tainted state variables
        """
        state_var = []
        if contract.is_top_level:
            return state_var
        for v in contract.state_variables:
            dep = {
                    d.name
                    for d in get_dependencies(v, contract)
                    if not isinstance(d, (TemporaryVariable, ReferenceVariable)) and d.name != v.name
                }
            if len(dep) > 0:
                state_var.append(v)
        return state_var

    # TODO: more accurate, state dependency taint analysis, 
    def get_tainted_state(self, contract):
        """
        Tainted state variables
        """
        state_var = []
        taint_state_var = []
        if contract.is_top_level:
            return state_var
        for v in contract.state_variables:
            dep = {
                    d.name
                    for d in get_dependencies(v, contract)
                    if not isinstance(d, (TemporaryVariable, ReferenceVariable)) and d.name != v.name
                }
            if len(dep) > 0:
                state_var.append(v)
        
        for func in contract.functions:
            if (
                func.visibility in ["private"]
                or func.is_constructor
                or func.is_fallback
                or func.is_constructor_variables
                or not func.is_implemented
            ):
                continue
            taints = func.parameters_ssa         # func.parameters or func.parameters_ssa
            taints = func.parameters
            taints += self.sources_taint
            taints += taint_state_var

            # Disable the detector on top level function until we have good taint on those
            if isinstance(func, FunctionTopLevel):
                return taint_nodes
            for node in func.nodes:
                # case Assignment Node: Explicit-taint-analysis (Data Dependency)
                if node.type in [NodeType.EXPRESSION, NodeType.VARIABLE] and not node.contains_require_or_assert() and not self.is_sensitive_operation(node): # msg.sender.transfer(REWARD) is also EXPRESSION
                    for ir in node.irs:             # node.irs_ssa
                        # Filter to only tainted
                        for var in ir.used:
                            if self.is_any_tainted([var], taints, func):
                                if not any([
                                    var.name == v.name
                                    for v in taints
                                ]):
                                    taints.append(var)
                                if var in state_var and not any([
                                    var.name == v.name
                                    for v in taint_state_var
                                ]):
                                    taint_state_var.append(var)
        return taint_state_var

    # TODO: state dependency taint analysis
    def get_tainted_state_ssa(self, contract):
        """
        Tainted state variables
        """
        res = []
        if contract.is_top_level:
            return res
        for v in contract._initial_state_variables:
            # GUESS_0, get_dependencies_ssa - GUESS_1
            dep = {
                    d.name
                    for d in get_dependencies_ssa(v, contract)
                    if not isinstance(d, (TemporaryVariable, ReferenceVariable)) and d.name != v.name
                }
            if len(dep) > 0:
                res.append(v.name) 
        return res

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            # funcs = contract.all_functions_called + contract.modifiers
            # non ssa
            self.state_var = self.get_state(contract)
            tainted_state = self.get_tainted_state(contract)
            self.global_taint_nodes = []
            self.access_control_state_var = contract.state_variables

            for func in contract.functions:
                if (
                    # func.visibility in ["private"]
                    func.is_constructor
                    or func.is_fallback
                    or func.is_constructor_variables
                    or not func.is_implemented
                ):
                    continue

                taint_nodes = self.detect_tod(func, tainted_state)
                
                if taint_nodes:
                    info = [func, " transaction ordering dependency\n"]
                    info += ["\tTransaction Ordering Dependency:\n"]
                    # sort the nodes to get deterministic results
                    taint_nodes.sort(key=lambda x: x.node_id)

                    for node in taint_nodes:
                        info += ["\t- ", node, "\n"]

                    res = self.generate_result(info)

                    results.append(res)

        return results