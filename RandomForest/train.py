import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from encoders import RobustLabelEncoder

def load_data(filepath):
    df = pd.read_csv(filepath)
    df.replace('-', 'unknown', inplace=True)
    
    cat_cols = ['proto', 'service', 'state']
    label_encoders = {}
    for col in cat_cols:
        le = RobustLabelEncoder()
        df[col] = df[col].fillna('unknown').astype(str)
        le.fit(df[col])
        df[col] = le.transform(df[col])
        label_encoders[col] = le
    
    X = df.drop(['id', 'label'], axis=1)
    y = df['label'].apply(lambda x: 0 if x == 0 else 1)
    return X, y, label_encoders



# 数据集划分（网页3[3](@ref)、网页5[5](@ref)方案）
def split_dataset(X, y):
    return train_test_split(
        X, y,
        test_size=0.3,
        random_state=42,
        stratify=y  # 保持类别分布（网页5[5](@ref)增强）
    )

# 模型训练（网页3[3](@ref)、网页4[4](@ref)参数优化）
def train_model(X_train, y_train):
    model = RandomForestClassifier(
        n_estimators=150,        # 树数量（网页3[3](@ref)推荐范围）
        max_depth=15,            # 限制树深防过拟合
        class_weight='balanced', # 处理类别不平衡（网页4[4](@ref)建议）
        max_features='sqrt',     # 特征选择策略（网页3[3](@ref)推荐）
        n_jobs=-1,               # 并行加速（网页5[5](@ref)优化）
        random_state=42
    )
    model.fit(X_train, y_train)
    return model

# 主流程（整合网页4[4](@ref)、网页5[5](@ref)工作流）
if __name__ == "__main__":
    # 数据准备
    X, y, encoders = load_data(r"./dataset/UNSW_NB15_training-set.csv")
    X_train, X_test, y_train, y_test = split_dataset(X, y)
    
    # 模型训练
    rf_model = train_model(X_train, y_train)
    
    # 模型评估（网页4[4](@ref)标准评估）
    y_pred = rf_model.predict(X_test)
    print(f"准确率: {accuracy_score(y_test, y_pred):.4f}")
    print("\n分类报告:")
    print(classification_report(y_test, y_pred))
    print("混淆矩阵:")
    print(confusion_matrix(y_test, y_pred))
    
    # 特征重要性分析（网页4[4](@ref)实现）
    feature_importance = pd.DataFrame({
        'Feature': X.columns,
        'Importance': rf_model.feature_importances_
    }).sort_values(by='Importance', ascending=False)
    print("\nTop 10重要特征:")
    print(feature_importance.head(10))
    
    # 模型保存（网页5[5](@ref)持久化方案）
    joblib.dump({
        'model': rf_model,
        'encoders': encoders
    }, 'ddos_detection_model.joblib')
    print("\n模型已保存为 ddos_detection_model.joblib")