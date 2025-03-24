# -*- coding: utf-8 -*-
"""UNSW-NB15测试集验证完整代码"""
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import (classification_report,
                             confusion_matrix,
                             ConfusionMatrixDisplay)
from sklearn.tree import DecisionTreeClassifier

# 1. 数据加载与特征对齐


def load_and_align(train_path, test_path):
    # 加载训练集（用于获取特征模板）
    train_df = pd.read_csv(train_path)
    train_df.replace('-', 'unknown', inplace=True)

    # 加载测试集
    test_df = pd.read_csv(test_path)
    test_df.replace('-', 'unknown', inplace=True)

    # 合并数据集确保特征对齐
    combined = pd.concat([train_df, test_df], axis=0)

    # 处理分类特征
    categorical_cols = ['proto', 'service', 'state']
    encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    encoded_features = encoder.fit_transform(combined[categorical_cols])

    # 分割回训练集和测试集
    train_size = len(train_df)
    train_encoded = encoded_features[:train_size]
    test_encoded = encoded_features[train_size:]

    # 构建最终数据集
    X_train = pd.concat([
        train_df.drop(['id', 'label'] + categorical_cols, axis=1),
        pd.DataFrame(train_encoded, columns=encoder.get_feature_names_out())
    ], axis=1)

    X_test = pd.concat([
        test_df.drop(['id', 'label'] + categorical_cols, axis=1),
        pd.DataFrame(test_encoded, columns=encoder.get_feature_names_out())
    ], axis=1)

    y_train = train_df['label'].apply(lambda x: 1 if x != 0 else 0)
    y_test = test_df['label'].apply(lambda x: 1 if x != 0 else 0)

    return X_train, X_test, y_train, y_test

# 2. 模型验证流程


def evaluate_model(model, X_test, y_test):
    # 预测与评估
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred,
                                target_names=['Normal', 'DDOS']))

    # 混淆矩阵可视化
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(cm,
                                  display_labels=model.classes_)
    disp.plot()
    plt.savefig('test_confusion_matrix.png')
    plt.close()

    # 特征重要性分析
    feat_importances = pd.Series(
        model.feature_importances_, index=X_test.columns)
    top20 = feat_importances.nlargest(20)
    plt.figure(figsize=(10, 6))
    top20.plot(kind='barh')
    plt.title('Top 20 Important Features (Test Set)')
    plt.savefig('test_feature_importance.png', bbox_inches='tight')


# 3. 主流程
if __name__ == "__main__":
    # 数据路径配置
    train_file = r"./dataset/UNSW_NB15_training-set.csv"
    test_file = r"./dataset/UNSW_NB15_testing-set.csv"

    # 特征对齐处理
    X_train, X_test, y_train, y_test = load_and_align(train_file, test_file)

    # 加载预训练模型（或重新训练）
    model = DecisionTreeClassifier(
        max_depth=5,
        min_samples_split=10,
        class_weight='balanced',
        random_state=42
    )
    model.fit(X_train, y_train)  # 若已有模型，可替换为加载代码

    # 执行验证
    evaluate_model(model, X_test, y_test)
    print("验证完成！结果已保存为PNG文件")
