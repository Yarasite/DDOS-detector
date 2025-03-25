from sklearn.preprocessing import LabelEncoder as BaseLabelEncoder
import numpy as np
import pandas as pd

class RobustLabelEncoder(BaseLabelEncoder):
    """ 增强型编码器（解决网页1、网页3问题） """
    def __init__(self):
        super().__init__()
        self.unknown_token = 'unknown'
        
    def fit(self, y):
        # 强制统一为字符串类型（关键修复点）
        y_str = pd.Series(y).astype(str)
        seen = np.unique(y_str)
        classes = np.append(seen, [self.unknown_token])
        return super().fit(classes)
    
    def transform(self, y):
        # 类型强制转换（解决网页5数据兼容问题）
        y_str = pd.Series(y).astype(str)
        y_processed = np.where(np.isin(y_str, self.classes_), y_str, self.unknown_token)
        return super().transform(y_processed)
    
    def inverse_transform(self, y):
        orig_classes = self.classes_[:-1]
        return [orig_classes[i] if i < len(orig_classes) else self.unknown_token 
                for i in y]
