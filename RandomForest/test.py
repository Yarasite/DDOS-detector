import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from encoders import RobustLabelEncoder

# test.py (修复断言逻辑部分)
def load_test_data(test_path, encoders):
    test_df = pd.read_csv(test_path)
    test_df.replace('-', 'unknown', inplace=True)
    
    for col in ['proto', 'service', 'state']:
        le = encoders[col]
        test_df[col] = test_df[col].astype(str)
        valid_values = set(le.classes_.astype(str))
        
        # 替换未知类别为'unknown'
        test_df[col] = test_df[col].apply(
            lambda x: x if x in valid_values else le.unknown_token
        )
        # 进行编码转换
        test_df[col] = le.transform(test_df[col])
    
    # 修正断言逻辑：验证编码值范围
    for col in ['proto', 'service', 'state']:
        le = encoders[col]
        max_code = len(le.classes_) - 1
        test_unique = set(test_df[col].unique())
        invalid_values = {v for v in test_unique if not 0 <= v <= max_code}
        
        assert not invalid_values, \
            f"{col}列存在无效编码值: {invalid_values} (最大允许值: {max_code})"
    
    X_test = test_df.drop(['id', 'label'], axis=1)
    y_test = test_df['label'].apply(lambda x: 0 if x == 0 else 1)
    return X_test, y_test

# 2. 模型加载与预测
def model_inference(model_path, X_test):
    # 加载训练阶段保存的完整对象
    saved_data = joblib.load(model_path)
    model = saved_data['model']
    
    # 确保输入特征与训练时完全一致
    X_test = X_test.reindex(columns=model.feature_names_in_, fill_value=0)
    
    # 生成预测结果
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    return y_pred, y_proba

# 3. 主执行流程
if __name__ == "__main__":
    # 加载预处理组件
    saved_data = joblib.load('ddos_detection_model.joblib')
    encoders = saved_data['encoders']
    
    # 数据准备
    X_test, y_test = load_test_data(
        r"./dataset/UNSW_NB15_testing-set.csv",
        encoders
    )
    
    # 模型预测
    y_pred, y_proba = model_inference("ddos_detection_model.joblib", X_test)
    
    # 4. 性能评估
    print("核心指标:")
    print(f"准确率: {accuracy_score(y_test, y_pred):.4f}")
    print(f"精确率: {precision_score(y_test, y_pred):.4f}")
    print(f"召回率: {recall_score(y_test, y_pred):.4f}")
    print(f"F1值: {f1_score(y_test, y_pred):.4f}\n")
    
    print("分类报告:")
    print(classification_report(y_test, y_pred, 
                               target_names=['正常流量', '攻击流量']))
    
    print("混淆矩阵:")
    print(confusion_matrix(y_test, y_pred))
    
    # 5. 结果持久化
    test_result = pd.DataFrame({
        '真实标签': y_test,
        '预测标签': y_pred,
        '攻击概率': y_proba
    })
    test_result.to_csv('model_predictions.csv', index=False)