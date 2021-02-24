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

impl<'a> Label<'a> {
    #[allow(dead_code)]
    pub fn get_str(&self) -> &'a str {
        match self {
            Self::Attribute(s) | Self::NotAttribute(s) => s,
        }
    }

}

#[derive(Debug, PartialEq, Eq)]
pub struct MSP<'a>(pub Vec<(Label<'a>, Vec<i8, S>), S>);

#[derive(Debug, PartialEq, Eq)]
pub struct Error;

impl<'a> MSP<'a> {
    /// Create MSP from an Access Tree (only AND and OR nodes)
    pub fn from_access_tree<'b>(t: AccessTree<'a, 'b>) -> Result<Self, Error> {
        let mut c = 1;
        let mut msp_inner = Self::lw_construction(t, &t[0], &mut c, Vec::from_slice(&[1]).unwrap())?;

        // still need to make sure all vector have the correct length (pad w/ zeroes)
        for (_, row) in msp_inner.iter_mut() {
            row.resize(c as usize, 0)?;
        }
        Ok(MSP(msp_inner))
    }

    /// recursively applies the construction from Appendix G, "Decentralizing Attribute-Based Encryption", Lewko and Waters, 2011
    /// 
    /// Note that the returned matrix's rows might not all have the same length.
    fn lw_construction<'b>(tree: AccessTree<'a, 'b>, current_node: &AccessNode<'a>, c: &mut u8, v: Vec<i8, S>) -> Result<Vec<(Label<'a>, Vec<i8, S>), S>, Error> {

        let (mut res_l, res_r) = match current_node {
            AccessNode::Or(l, r) => (Self::lw_construction(tree, &tree[*l as usize], c, v.clone())?, Self::lw_construction(tree, &tree[*r as usize], c, v.clone())?),
            AccessNode::And(l, r) => {
                let mut v_l = v;
                v_l.resize(*c as usize, 0)?;
                v_l.push(1)?;

                let mut v_r = Vec::new();
                v_r.resize(*c as usize, 0)?;
                v_r.push(-1i8)?;

                *c += 1;

                (Self::lw_construction(tree, &tree[*l as usize], c, v_l)?, Self::lw_construction(tree, &tree[*r as usize], c, v_r)?)
            },
            AccessNode::Leaf(s) => {
                let mut row = Vec::new();
                match row.push((Label::Attribute(s), v)) {
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

    pub fn prune<'b, 'c>(t: AccessTree<'a, 'b>, atts: &[&'c str]) -> Result<Vec<&'a str, S>, Error> {
        Self::prune_rec(t, &t[0], atts)
    }

    fn prune_rec<'c>(t: &[AccessNode<'a>], current_node: &AccessNode<'a>, atts: &[&str]) -> Result<Vec<&'a str, S>, Error> {
         let req = match current_node {
            AccessNode::And(l, r) => {
                let mut l_req = Self::prune_rec(t, &t[*l as usize], atts)?;
                let r_req = Self::prune_rec(t, &t[*r as usize], atts)?;
                l_req.extend(r_req.into_iter());
                l_req
            },
            AccessNode::Or(l, r) => { // return the left side if it is satisfied, otherwise the right
                if let Ok(req) = Self::prune_rec(t, &t[*l as usize], atts) {
                    req
                } else {
                    match Self::prune_rec(t, &t[*r as usize], atts) {
                        Ok(req) => req,
                        Err(_) => return Err(Error),
                    }
                }
            },
            AccessNode::Leaf(a) => {
                match atts.iter().filter(|a_| *a_ == a).count() > 0 {
                    false => return Err(Error),
                    true => {
                        let mut r = Vec::new();
                        r.push(*a)?;
                        r
                    },
                }
            }
        };
        Ok(req)
    }
}

impl<'a> IntoIterator for MSP<'a> {
    type Item = <heapless::Vec<(Label<'a>, Vec<i8, S>), S> as IntoIterator>::Item;
    type IntoIter = <heapless::Vec<(Label<'a>, Vec<i8, S>), S> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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

impl From<&str> for Error {
    fn from(_: &str) -> Error{
        Error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::Label::*;

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

        // sort by attribute name -> otherwise the comparison would fail 
        // this is ugly because we need to extract the str-slice that is contained either in the Attribute or NotAttribute variant of the Label enum
        msp.sort_by(|(l1, _), (l2,_)| {
            l1.get_str().cmp(l2.get_str())
        });

        // println!("{:?}", &msp);
        
        assert_eq!(&msp[..], expected);
        
    }

    #[test]
    fn test_prune() {
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

        let att_all = &["A", "B", "C", "D"];
        assert_eq!(MSP::prune(tree, att_all).unwrap(), &["A", "D"]);

        let att_satisfies = &["B", "A", "C"];
        assert_eq!(MSP::prune(tree, att_satisfies).unwrap(), &["A", "B", "C"]);

        let att_insufficient = &["B", "C"];
        assert_eq!(MSP::prune(tree, att_insufficient), Err(Error));
    }

    #[test]
    fn test_reconstruct() {
        let tree = &[
            AccessNode::And(1, 2),  // 0
            AccessNode::Leaf("A"),  // 1
            AccessNode::Or(3, 4),   // 2
            AccessNode::Leaf("D"),  // 3
            AccessNode::And(5, 6),  // 4
            AccessNode::Leaf("B"),  // 5
            AccessNode::Leaf("C"),  // 6
        ];


        let msp = MSP::from_access_tree(tree).unwrap();

        let m_i: Vec<(Label, Vec<i8, S>), S> = msp.0.into_iter().filter(|(l, _)| l.get_str() == "A" || l.get_str() == "D").collect();

        let pruned = MSP::prune(tree, &["A", "D"]).unwrap();

        let mut res: Vec<i8, S> = Vec::new();
        res.resize(m_i[0].1.len(), 0).unwrap();
        for (l, row) in m_i.into_iter() {
            let coeff = if pruned.iter().filter(|x| l.get_str() == **x).count() != 0 { 1 } else { 0 };
            for (acc, x) in res.iter_mut().zip(row.iter()) {
                *acc += coeff * x;
            }
        }

        let mut solution_vec: Vec<i8, S> = Vec::new();
        solution_vec.push(1).unwrap();
        solution_vec.resize(res.len(), 0).unwrap();
        assert_eq!(res, solution_vec);
    }
}