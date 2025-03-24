# -*- coding: utf-8 -*-
"""DDOS检测决策树模型完整实现"""
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report,
                             confusion_matrix,
                             ConfusionMatrixDisplay)
from sklearn.preprocessing import LabelEncoder

# 1. 数据加载与预处理


def load_data(path):
    df = pd.read_csv(path)

    # 处理特殊字符'-'为单独类别
    df.replace('-', 'unknown', inplace=True)

    # 标签二值化
    df['label'] = df['label'].apply(lambda x: 1 if x != 0 else 0)

    # 类别特征编码
    categorical_cols = ['proto', 'service', 'state']
    df = pd.get_dummies(df, columns=categorical_cols)

    return df

# 2. 特征工程


def feature_engineering(df):
    # 移除无关特征
    X = df.drop(['id', 'label'], axis=1)
    y = df['label']

    # 处理类别不平衡（可选）
    # 此处可添加SMOTE过采样代码

    return X, y

# 3. 模型训练


def train_model(X_train, y_train):
    model = DecisionTreeClassifier(
        max_depth=5,          # 限制树深度防止过拟合[1,7](@ref)
        min_samples_split=10,  # 节点最小分裂样本数
        class_weight='balanced',  # 处理类别不平衡[7](@ref)
        random_state=42
    )
    model.fit(X_train, y_train)
    return model

# 4. 可视化工具


def visualize(model, X_cols):
    plt.figure(figsize=(25, 15))
    plot_tree(model,
              feature_names=X_cols,
              class_names=['Normal', 'DDOS'],
              filled=True,
              rounded=True,
              proportion=True)
    plt.savefig('decision_tree.png', dpi=300)

    # 特征重要性可视化
    feat_importances = pd.Series(model.feature_importances_, index=X_cols)
    top20 = feat_importances.nlargest(20)
    plt.figure(figsize=(10, 6))
    top20.plot(kind='barh')
    plt.title('Top 20 Important Features')
    plt.savefig('feature_importance.png', bbox_inches='tight')


# 5. 主流程
if __name__ == "__main__":
    # 数据加载
    df = load_data(r"./dataset/UNSW_NB15_training-set.csv")

    # 特征工程
    X, y = feature_engineering(df)

    # 数据集划分
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    # 模型训练
    model = train_model(X_train, y_train)

    # 模型评估
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred,
                                target_names=['Normal', 'DDOS']))

    # 混淆矩阵
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(cm,
                                  display_labels=model.classes_)
    disp.plot()
    plt.savefig('confusion_matrix.png')

    # 可视化输出
    visualize(model, X.columns.tolist())

    print("模型训练完成！可视化结果已保存为png文件")
