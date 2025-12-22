
// src/main.rs

// 确保 Cargo.toml 包含
// [dependencies]
// libcrux_ml_kem = { path = "../path/to/libcrux_ml_kem", features = ["mlkem768", "tkem768"] }
// rand = "0.8"
// hex = "0.4" // 用于 main 函数中的打印，测试中不一定需要

// 注意：测试通常使用 dev-dependencies，如果 hex 只在测试中用到
// [dev-dependencies]
// hex = "0.4"

use libcrux_ml_tkem::{mlkem768, tkem768, ENCAPS_SEED_SIZE, KEY_GENERATION_SEED_SIZE};
use rand::{rngs::OsRng, TryRngCore};

// --- 你的 main 函数 ---
// fn main() { ... }

// --- 单元测试 ---
// `#[cfg(test)]` 属性告诉 Rust 编译器只在运行测试时才编译这部分代码。
#[cfg(test)]
mod tests {
    // `use super::*;` 将外部作用域（即 main.rs 的根作用域）的所有内容引入到 tests 模块中。
    // 这样我们就可以直接访问 libcrux_ml_kem, rand, 以及常量等。
    use super::*;

    /// 测试 T-KEM-768 的封装和解封装一致性
    /// 注意：此测试混用了 ML-KEM-768 生成的密钥和 T-KEM-768 的操作，
    /// 这在现实中可能不工作，仅作示例。理想情况下应使用 tkem768::generate_key_pair。
    #[test]
    fn test_tkem768_encaps_decaps_consistency_with_ml_kem_keypair() {
        // 1. 设置固定的随机种子（为了测试的可重复性，也可以使用 OsRng）
        //    这里使用 OsRng 以模拟真实场景
        let mut keygen_randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.try_fill_bytes(&mut keygen_randomness).unwrap();

        // 2. 生成密钥对 (使用 ML-KEM-768)
        let key_pair = mlkem768::generate_key_pair(keygen_randomness);

        // 3. 设置封装随机种子
        let mut encap_randomness = [0u8; ENCAPS_SEED_SIZE];
        OsRng.try_fill_bytes(&mut encap_randomness).unwrap();

        // 4. 设置标签
        let test_tag = b"ConsistencyTestTag";

        // 5. 执行封装 (使用 T-KEM-768)
        // 注意：传递 encap_randomness 的引用
        let (ciphertext, shared_secret_encap) =
            tkem768::encapsulate_with_tag(key_pair.public_key(), encap_randomness, test_tag);

        // 6. 执行解封装 (使用 T-KEM-768)
        let shared_secret_decap =
            tkem768::decapsulate_with_tag(key_pair.private_key(), &ciphertext, test_tag);

        // 7. 断言共享秘密相等
        // 使用 .as_slice() 获取字节切片进行比较
        assert_eq!(
            shared_secret_encap.as_slice(),
            shared_secret_decap.as_slice(),
            "Encapsulated and Decapsulated shared secrets should be equal."
        );
        // 可选：也断言随机种子不全为零（简单检查）
        // assert!(!encap_randomness.iter().all(|&b| b == 0), "Encapsulation randomness was all zero.");

        // 测试通过，如果 assert_eq! 没有 panic
    }


    /// 更符合逻辑的测试：使用 T-KEM-768 生成密钥对进行测试
    #[test]
    fn test_tkem768_encaps_decaps_consistency_correct() {
        // 1. 设置随机种子
        let mut keygen_randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.try_fill_bytes(&mut keygen_randomness);

        // 2. 生成密钥对 (使用 T-KEM-768)
        // 假设 tkem768 有自己的 KeyPair 类型和 generate_key_pair 函数
        // 你需要根据实际 API 调整这一行
        // let key_pair = tkem768::generate_key_pair(keygen_randomness);

        // --- 以下为伪代码，展示理想情况下的结构 ---
        /*
        let mut encap_randomness = [0u8; ENCAPS_SEED_SIZE];
        OsRng.fill_bytes(&mut encap_randomness);

        let test_tag = b"CorrectFlowTestTag";

        // 3. 执行封装
        let (ciphertext, shared_secret_encap) =
            tkem768::encapsulate_with_tag(key_pair.public_key(), &encap_randomness, test_tag);

        // 4. 执行解封装
        let shared_secret_decap =
            tkem768::decapsulate_with_tag(key_pair.private_key(), &ciphertext, test_tag);

        // 5. 断言相等
        assert_eq!(
            shared_secret_encap.as_slice(),
            shared_secret_decap.as_slice(),
            "Shared secrets should match in correct flow."
        );
        */
        // --- 伪代码结束 ---
        // 请根据 tkem768 模块的实际 API 实现这部分
    }

    /// 测试 ML-KEM-768 的封装和解封装一致性 (如果适用)
    #[test]
    fn test_mlkem768_encaps_decaps_consistency() {
         // 类似地，为 ML-KEM-768 编写测试
         // 使用 mlkem768::generate_key_pair, mlkem768::encapsulate, mlkem768::decapsulate
         // 注意 ML-KEM 通常没有标签(tag)参数
    }

}

// --- main 函数 ---
fn main() {
    // ... 你之前的 main 函数代码 ...
}