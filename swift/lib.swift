/*******************************************

 Use:
 let key: [UInt32] = [0x00,0x01,0x02,0x03]
 var val: [UInt32] = [0x00,0x01]
 encrypt(Value: &val, Key: key)
 print(val)
 decrypt(Value: &val, Key: key)

 print(val)

 ******************************************/

import Foundation

func encrypt( Value v: inout [UInt32],Key k: [UInt32]) ->[UInt32] {
    var v0 : UInt32 = v[0]
    var v1 : UInt32 = v[1]

    var sum : UInt32 = 0
    /* set up */
    let delta : UInt32 = 0x9e3779b9/* a key schedule constant */

    for _ in 0...31 {/* basic cycle start */

        sum = sum &+ delta

        v0 = v0 &+ (((v1<<4) &+ k[0]) ^ (v1 &+ sum) ^ ((v1>>5) &+ k[1]))

        v1 = v1 &+ (((v0<<4) &+ k[2]) ^ (v0 &+ sum) ^ ((v0>>5) &+ k[3]))

    }
    v[0] = v0
    v[1] = v1

    return v
}

func decrypt ( Value v : inout [UInt32],Key k : [UInt32]) ->[UInt32] {
    var  v0 : UInt32 = v[0]
    var v1 : UInt32 = v[1]
    var sum : UInt32 = 0xC6EF3720  /* set up */
    let delta : UInt32 = 0x9e3779b9                     /* a key schedule constant */

    for _ in 0...31 {/* basic cycle start */

        v1 = v1 &- (((v0<<4) &+ k[2]) ^ (v0 &+ sum) ^ ((v0>>5) &+ k[3]))
        v0 = v0 &- (((v1<<4) &+ k[0]) ^ (v1 &+ sum) ^ ((v1>>5) &+ k[1]))
        sum = sum &- delta

    }
    v[0] = v0
    v[1] = v1
    return v
}
