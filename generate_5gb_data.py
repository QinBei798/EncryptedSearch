import os
import random

def generate_data():
    out_dir = "test_docs_5gb"
    os.makedirs(out_dir, exist_ok=True)
    
    base_sentences = [
        "加密算法在现代信息安全中起着至关重要的作用，特别是国密算法。\n",
        "国密标准包括SM2、SM3、SM4等，能够提供国密级安全保障。\n",
        "结巴分词是一个非常流行的C++和Python中文分词库，支持CutForSearch。\n",
        "倒排索引是搜索引擎的核心数据结构，结合ESIX磁盘懒加载可以大幅提升效率。\n",
        "布尔搜索允许用户通过AND、OR、NOT等逻辑运算符组合查询。\n",
        "使用C++17标准可以带来很多现代化的语言特性支持，配合Intel Core CPU多线程效果更佳。\n",
        "多线程并行计算可以显著提高系统的吞吐量和资源利用率，CPU算力利用率稳定。\n",
        "流式I/O与OOM防御策略在处理海量数据时显得尤为重要。\n"
    ]
    
    # 目标文件大小约 1MB
    target_size = 1024 * 1024
    
    print(f"正在 {out_dir} 目录下生成 5,000 份文档...")
    print("这可能需要几分钟时间，并将占用约 5GB 磁盘空间，请确保您的磁盘空间充足！")
    
    # 预先生成几个不同的 1MB 随机数据块，以增加差异性，避免完全一样的哈希
    blocks = []
    for _ in range(10):
        block = ""
        while len(block.encode('utf-8')) < target_size:
            block += random.choice(base_sentences)
        blocks.append(block)
    
    for i in range(5000):
        file_path = os.path.join(out_dir, f"doc_{i:05d}.txt")
        # 写入随机的数据块
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(random.choice(blocks))
            # 随机在文件末尾插入一些特定关键词，模拟真实分布
            if random.random() < 0.1:
                f.write("\n特别测试：加密 AND NOT 分词 的边界条件验证。\n")
                
        if (i + 1) % 500 == 0:
            print(f"已生成 {i + 1} 份文件...")
            
    print("5GB 实验数据生成完毕！您可以运行 main 验证真实性能了。")

if __name__ == "__main__":
    generate_data()
