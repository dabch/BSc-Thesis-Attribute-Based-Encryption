#!/usr/bin/env python3

MAX_LEVELS = 3
CHILDREN_PER_LEVEL = 3

ctr = 1
print("""
    #[macro_export]
    macro_rules! policy_deep_%d {
        () => {""" % (CHILDREN_PER_LEVEL))

print("&[")
for levels in range(1, 1+ MAX_LEVELS):
    # levels = number of levels of current tree
    print("&[")
    ctr = 1
    for l in range(levels):
        # level of current tree to deal with
        for j in range(CHILDREN_PER_LEVEL** l):
            node_ids = map(lambda i: str(ctr + i), range(CHILDREN_PER_LEVEL))
            print(f'AccessNode::Node({CHILDREN_PER_LEVEL}, Vec::from_slice(&[{",".join(node_ids)}]).unwrap()),')
            ctr += CHILDREN_PER_LEVEL
    for j in range(CHILDREN_PER_LEVEL ** (l+1)):
        print(f'AccessNode::Leaf("att%02d"),' % ((j % 30)+1))
    print("],")
print("]")
print("""};
}""")
# print("
        