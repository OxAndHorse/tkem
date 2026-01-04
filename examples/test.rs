
use libcrux_ml_tkem::{ tkem768,kyber768, tkem1024, kyber1024,  ENCAPS_SEED_SIZE, KEY_GENERATION_SEED_SIZE};
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
    fn test_tkem768() {
        // 1. 设置固定的随机种子（为了测试的可重复性，也可以使用 OsRng）
        //    这里使用 OsRng 以模拟真实场景
        let mut keygen_randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.try_fill_bytes(&mut keygen_randomness).unwrap();

        // 2. 生成密钥对 (使用 ML-KEM-768)
        let key_pair = tkem768::generate_key_pair(keygen_randomness);

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

    }

    #[test]
    fn test_tkem1024() {
        // 1. 设置固定的随机种子（为了测试的可重复性，也可以使用 OsRng）
        //    这里使用 OsRng 以模拟真实场景
        let mut keygen_randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.try_fill_bytes(&mut keygen_randomness).unwrap();

        // 2. 生成密钥对 (使用 ML-KEM-768)
        let key_pair = tkem1024::generate_key_pair(keygen_randomness);

        // 3. 设置封装随机种子
        let mut encap_randomness = [0u8; ENCAPS_SEED_SIZE];
        OsRng.try_fill_bytes(&mut encap_randomness).unwrap();

        // 4. 设置标签
        let test_tag = b"ConsistencyTestTag";

        // 5. 执行封装 (使用 T-KEM-768)
        // 注意：传递 encap_randomness 的引用
        let (ciphertext, shared_secret_encap) =
            tkem1024::encapsulate_with_tag(key_pair.public_key(), encap_randomness, test_tag);

        // 6. 执行解封装 (使用 T-KEM-768)
        let shared_secret_decap =
            tkem1024::decapsulate_with_tag(key_pair.private_key(), &ciphertext, test_tag);

        // 7. 断言共享秘密相等
        // 使用 .as_slice() 获取字节切片进行比较
        assert_eq!(
            shared_secret_encap.as_slice(),
            shared_secret_decap.as_slice(),
            "Encapsulated and Decapsulated shared secrets should be equal."
        );

    }

    #[test]
    // #[cfg(feature = "kyber")]
    fn kyber768_with_tag(){
        let mut keygen_randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.try_fill_bytes(&mut keygen_randomness).unwrap();

        // 2. 生成密钥对 (使用 ML-KEM-768)
        let key_pair = kyber768::generate_key_pair1(keygen_randomness);

        // 3. 设置封装随机种子
        let mut encap_randomness = [0u8; ENCAPS_SEED_SIZE];
        OsRng.try_fill_bytes(&mut encap_randomness).unwrap();

        // 4. 设置标签
        let test_tag = b"ConsistencyTestTag";

        let (ciphertext, shared_secret_encap) =
            kyber768::encapsulate_with_tag(key_pair.public_key(), encap_randomness, test_tag);

        // 6. 执行解封装 (使用 T-KEM-768)
        let shared_secret_decap =
            kyber768::decapsulate_with_tag(key_pair.private_key(), &ciphertext, test_tag);

        // 7. 断言共享秘密相等
        // 使用 .as_slice() 获取字节切片进行比较
        assert_eq!(
            shared_secret_encap.as_slice(),
            shared_secret_decap.as_slice(),
            "Encapsulated and Decapsulated shared secrets should be equal."
        );

    }

    #[test]
    fn kyber1024_with_tag(){
        let mut keygen_randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.try_fill_bytes(&mut keygen_randomness).unwrap();

        // 2. 生成密钥对 (使用 ML-KEM-768)
        let key_pair = kyber1024::generate_key_pair1(keygen_randomness);

        // 3. 设置封装随机种子
        let mut encap_randomness = [0u8; ENCAPS_SEED_SIZE];
        OsRng.try_fill_bytes(&mut encap_randomness).unwrap();

        // 4. 设置标签
        let test_tag = b"ConsistencyTestTag";

        let (ciphertext, shared_secret_encap) =
            kyber1024::encapsulate_with_tag(key_pair.public_key(), encap_randomness, test_tag);

        // 6. 执行解封装 (使用 T-KEM-768)
        let shared_secret_decap =
            kyber1024::decapsulate_with_tag(key_pair.private_key(), &ciphertext, test_tag);

        // 7. 断言共享秘密相等
        // 使用 .as_slice() 获取字节切片进行比较
        assert_eq!(
            shared_secret_encap.as_slice(),
            shared_secret_decap.as_slice(),
            "Encapsulated and Decapsulated shared secrets should be equal."
        );

    }
    

}

// --- main 函数 ---
fn main() {

    
}