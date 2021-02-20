use heapless::{Vec, consts};

type S = consts::U8;

#[derive(Debug)]
pub enum AccessNode<'attr> {
  And(u8, u8), // left child, right child
  Or(u8, u8),
  Leaf(&'attr str),
}


/// Represents an access structure defined as a threshold-tree
// Implementation: Array of 256 AccessNodes, the first one is the root
// size of this is 10248 bytes (!)
// pub type AccessStructure<'a> = Vec<AccessNode<'a>, consts::U256>; 
pub type AccessTree<'attr, 'own> = &'own [AccessNode<'attr>];

#[derive(Debug, PartialEq, Eq)]
pub enum Label<'a> {
    Attribute(&'a str),
    NotAttribute(&'a str),
}

#[derive(Debug, PartialEq, Eq)]
pub struct MSP<'a>(Vec<(Label<'a>, Vec<i8, S>), S>);

#[derive(Debug)]
pub struct Error;

impl<'a> MSP<'a> {
    /// Create MSP from an Access Tree (only AND and OR nodes)
    pub fn from_access_tree<'b>(t: AccessTree<'a, 'b>) -> Result<Self, Error> {
        let mut c = 1;
        let mut msp_inner = Self::lw_construction(t, &t[0], &mut c, Vec::from_slice(&[1]).unwrap())?;
        for (_, row) in msp_inner.iter_mut() {
            row.resize(c as usize, 0)?;
        }
        Ok(MSP(msp_inner))
    }

    fn lw_construction<'b>(tree: AccessTree<'a, 'b>, current_node: &AccessNode<'a>, c: &mut u8, node_label: Vec<i8, S>) -> Result<Vec<(Label<'a>, Vec<i8, S>), S>, Error> {

        // std::println!("{}", *c);
        let (mut res_l, res_r) = match current_node {
            AccessNode::Or(l, r) => (Self::lw_construction(tree, &tree[*l as usize], c, node_label.clone())?, Self::lw_construction(tree, &tree[*r as usize], c, node_label.clone())?),
            AccessNode::And(l, r) => {
                let mut v_l = node_label.clone();
                v_l.resize(*c as usize, 0)?;
                v_l.push(1)?;

                let mut v_r = Vec::new();
                v_r.resize(*c as usize, 0)?;
                v_r.push(-1i8)?;

                std::println!("increment c = {} + 1", *c);
                *c += 1;

                (Self::lw_construction(tree, &tree[*l as usize], c, v_l)?, Self::lw_construction(tree, &tree[*r as usize], c, v_r)?)
            },
            AccessNode::Leaf(s) => {
                std::println!("labelling {} with c={}", s, *c);
                let mut row = Vec::new();
                match row.push((Label::Attribute(s), node_label)) {
                    Ok(_) => (),
                    Err(_) => return Err(Error),
                }
                return Ok(row)
            },
        };
        for row in res_r {
            match res_l.push(row) {
                Ok(_) => (),
                Err(_) => return Err(Error),
            };
        }
        Ok(res_l)
    }
}

impl From<i8> for Error {
    fn from(_: i8) -> Error {
        Error
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Error{
        Error
    }
}

#[cfg(test)]
mod tests {
    // extern crate std;
    // use std::prelude::v1::*;
    use super::*;
    use super::Label::*;

    use std::println;

    #[test]
    fn tree_to_msp() {
        // this is the example from Lewko and Waters 2011, Appendix G

        // access policy: A AND (D OR (B AND C))
        let tree = &[
            AccessNode::And(1, 2),  // 0
            AccessNode::Leaf("A"),  // 1
            AccessNode::Or(3, 4),   // 2
            AccessNode::Leaf("D"),  // 3
            AccessNode::And(5, 6),  // 4
            AccessNode::Leaf("B"),  // 5
            AccessNode::Leaf("C"),  // 6
        ];


        let expected: &[(Label, Vec<i8, S>)] = &[
            (Attribute("A"), Vec::from_slice(&[1, 1, 0]).unwrap()),
            (Attribute("B"), Vec::from_slice(&[0, -1, 1]).unwrap()),
            (Attribute("C"), Vec::from_slice(&[0, 0, -1]).unwrap()),
            (Attribute("D"), Vec::from_slice(&[0, -1, 0]).unwrap()),
        ];

        let mut msp = MSP::from_access_tree(tree).unwrap().0;
        println!("{:?}", &msp);


        // sort by attribute name -> otherwise the comparison would fail 
        // this is ugly because we need to extract the str-slice that is contained either in the Attribute or NotAttribute variant of the Label enum
        msp.sort_by(|(l1, _), (l2,_)| {
            match (l1, l2) {
                (Attribute(s1), Attribute(s2)) | (NotAttribute(s1), Attribute(s2)) | (Attribute(s1), NotAttribute(s2)) | (NotAttribute(s1), NotAttribute(s2)) => s1.cmp(s2),
            }
        });

        // println!("{:?}", &msp);
        
        assert_eq!(&msp[..], expected);
        
    }
}