#!/usr/bin/env python3

from abc import ABC, abstractmethod
import random

SET_COUNT = 1
POLICY_COUNT = 30

total_count = 0

atts = ["att01", "att02", "att03", "att04", "att05", "att06", "att07", "att08", "att09", "att10", "att11", "att12", "att13", "att14", "att15", "att16", "att17", "att18", "att19", "att20", "att21", "att22", "att23", "att24", "att25", "att26", "att27", "att28", "att29", "att30"]

res = ""

class Tree(ABC):
    layers = 1
    ctr = 1
    res = []
    def __init__(self):
        # self.cap = cap
        self.free = 0

    @abstractmethod
    def randgen(self):
        pass

    @abstractmethod
    def to_rust(self, root):
        pass


class Node(Tree):
    
    def __init__(self, thresh, children):
        assert children is not None
        self.children = children
        self.thresh = thresh

    def randgen(self):
        # print(self.children)
        if random.randint(0,4) == 0: # insert into the current node (25% probability)
            newleaf = Leaf(random.sample(atts, 1)[0])
            self.children.append(newleaf)
            if random.randint(0,4) != 0: # raise the current threshold (or not)
                self.thresh += 1
            return self
        else:
            index = random.randint(0,len(self.children)-1)
            self.children[index] = self.children[index].randgen()
            return self
    
    def insert(self, i):
        self.thresh += 1
        self.children.append(Leaf(atts[i]))
        return self

    def __str__(self) -> str:
        # print(self.children)
        children_str = map(lambda c: str(c), self.children)
        return f"Node({self.thresh}, {', '.join(children_str)})"
    
    def to_rust(self, root):
        if root:
            Tree.res = []
            Tree.ctr = 1

        child_idx = map(lambda u: str(u.to_rust(False)), self.children)
        if not root:
            Tree.res.append(f'AccessNode::Node({self.thresh}, Vec::from_slice(&[{",".join(child_idx)}]).unwrap()),')
        if root:
            return "\n".join([f'AccessNode::Node({self.thresh}, Vec::from_slice(&[{",".join(child_idx)}]).unwrap()),'] + Tree.res)
        idx = Tree.ctr
        Tree.ctr += 1
        return idx

class Leaf(Tree):

    def __init__(self, attname):
        self.att = attname
    
    def randgen(self) -> Tree:
        newleaf = Leaf(random.sample(atts, 1)[0])
        otherleaf = self
        return Node(random.randint(1,2), [newleaf, otherleaf])

    def insert(self, i) -> Tree:
        newleaf = Leaf(atts[i])
        return Node(2, [self, newleaf])

    def __str__(self) -> str:
        return f"Leaf({self.att})"

    def to_rust(self, root):
        if root:
            Tree.res = []
            Tree.ctr = 1
        
        idx = Tree.ctr
        Tree.ctr += 1
        Tree.res.append(f'AccessNode::Leaf("{self.att}"),')
        if root:
            return "\n".join(Tree.res)

        return idx


tree = Leaf(atts[0])

# print(tree.to_rust())
for i in range(SET_COUNT):
    print("""
    #[macro_export]
    macro_rules! policy_%d {
        () => {""" % (2 //2))
    print("&[")
    print("&[")
    total_count = 0
    tree = Leaf(atts[0])
    res = ""
    for i in range(POLICY_COUNT):
        print("&[")
        print(tree.to_rust(True))
        print("],")
        tree = tree.insert(i)
    print("],")
print("]")
print("""};
}""")
# print("AccessNode::Node(1, Vec::from_slice[&[]).unwrap()),")
# print(tree.to_rust(True))