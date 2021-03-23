#!/usr/bin/env python3

from abc import ABC, abstractmethod
import random

POLICY_COUNT = 30

total_count = 0

class Tree(ABC):
    layers = 1
    def __init__(self):
        # self.cap = cap
        self.free = 0

    @abstractmethod
    def insert(self, att):
        pass

class Node(Tree):
    
    def __init__(self, thresh, free, left, right):
        # super().__init__(cap)
        self.left = left
        self.right = right
        self.thresh = thresh
        self.free = free

    def insert(self, att) -> Tree:
        # left side should always be full
        assert self.left.free == 0
        if self.free > 0:
            self.right = self.right.insert(att)
            self.free -= 1
            return self
        else:
            self.free = 2 ** self.left.layer() - 1
            right = Leaf(att, self.free)
            new = Node(random.randint(1,2), 2 ** Tree.layers, self, right)
            
            return new
        
    def layer(self) -> int:
        return self.left.layer() + 1

    def __str__(self) -> str:
        return f"Node({self.thresh}, {self.free}, {str(self.left)}, {str(self.right)})"

class Leaf(Tree):

    def __init__(self, attname, free):
        self.att = attname
        self.free = free
    
    def insert(self, att) -> Tree:

        newleaf = Leaf(att, self.free - 1)
        newnode = Node(random.randint(1,2), 0, self, newleaf)
        return newnode

    def layer(self) -> int:
        return 1

    def __str__(self) -> str:
        return f"Leaf({self.free}:{self.att})"



tree = Leaf("att0", 0)

for i in range(1, 4): 
    tree = tree.insert(f"att{i}")
    print(tree)
