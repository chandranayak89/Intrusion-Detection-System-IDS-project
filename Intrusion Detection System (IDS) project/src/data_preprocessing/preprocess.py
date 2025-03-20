#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Data Preprocessing Module
This module handles the preprocessing of network traffic data for the IDS.
"""

import os
import logging
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.impute import SimpleImputer

# Setup logging
logger = logging.getLogger('ids.preprocess')

def load_dataset(file_path):
    """
    Load a dataset from a file.
    
    Args:
        file_path (str): Path to the dataset file
        
    Returns:
        pandas.DataFrame: Loaded dataset
    """
    logger.info(f"Loading dataset from {file_path}")
    
    try:
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.csv':
            df = pd.read_csv(file_path)
        elif file_extension == '.parquet':
            df = pd.read_parquet(file_path)
        elif file_extension in ['.xls', '.xlsx']:
            df = pd.read_excel(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_extension}")
            
        logger.info(f"Loaded dataset with shape: {df.shape}")
        return df
    except Exception as e:
        logger.error(f"Error loading dataset: {e}")
        raise

def clean_data(df):
    """
    Clean the dataset by handling missing values, duplicates, etc.
    
    Args:
        df (pandas.DataFrame): Input dataset
        
    Returns:
        pandas.DataFrame: Cleaned dataset
    """
    logger.info("Cleaning dataset")
    
    # Make a copy to avoid modifying the original dataframe
    df_cleaned = df.copy()
    
    # Handle missing values
    logger.info(f"Missing values before cleaning: {df_cleaned.isna().sum().sum()}")
    
    # For numeric columns, fill with median
    numeric_cols = df_cleaned.select_dtypes(include=[np.number]).columns
    if not numeric_cols.empty:
        imputer = SimpleImputer(strategy='median')
        df_cleaned[numeric_cols] = imputer.fit_transform(df_cleaned[numeric_cols])
    
    # For categorical columns, fill with the most frequent value
    cat_cols = df_cleaned.select_dtypes(include=['object', 'category']).columns
    if not cat_cols.empty:
        for col in cat_cols:
            df_cleaned[col] = df_cleaned[col].fillna(df_cleaned[col].mode()[0])
    
    # Remove duplicate rows
    initial_rows = df_cleaned.shape[0]
    df_cleaned = df_cleaned.drop_duplicates()
    logger.info(f"Removed {initial_rows - df_cleaned.shape[0]} duplicate rows")
    
    logger.info(f"Missing values after cleaning: {df_cleaned.isna().sum().sum()}")
    
    return df_cleaned

def extract_features(df, label_column=None):
    """
    Extract features and labels from the dataset.
    
    Args:
        df (pandas.DataFrame): Input dataset
        label_column (str, optional): Name of the label/target column
        
    Returns:
        tuple: (features, labels) if label_column is provided, otherwise features only
    """
    logger.info("Extracting features")
    
    # Make a copy to avoid modifying the original dataframe
    df_features = df.copy()
    
    # Convert categorical features to numeric
    cat_cols = df_features.select_dtypes(include=['object', 'category']).columns
    for col in cat_cols:
        if col != label_column:  # Don't encode the label column yet
            df_features[col] = pd.factorize(df_features[col])[0]
    
    # If label column is provided, separate features and labels
    if label_column is not None and label_column in df_features.columns:
        logger.info(f"Separating features and labels using column: {label_column}")
        y = df_features[label_column]
        X = df_features.drop(columns=[label_column])
        
        # Encode label if it's categorical
        if y.dtype == 'object' or y.dtype.name == 'category':
            y = pd.factorize(y)[0]
            
        return X, y
    else:
        logger.info("No label column provided or found, returning features only")
        return df_features

def normalize_features(features, scaler_type='standard'):
    """
    Normalize the features using specified scaler.
    
    Args:
        features (pandas.DataFrame): Features to normalize
        scaler_type (str): Type of scaler to use ('standard', 'minmax')
        
    Returns:
        pandas.DataFrame: Normalized features
    """
    logger.info(f"Normalizing features using {scaler_type} scaler")
    
    if scaler_type == 'standard':
        scaler = StandardScaler()
    elif scaler_type == 'minmax':
        scaler = MinMaxScaler()
    else:
        raise ValueError(f"Unsupported scaler type: {scaler_type}")
    
    # Preserve column names
    feature_names = features.columns
    
    # Normalize features
    normalized_features = scaler.fit_transform(features)
    
    # Convert back to DataFrame with original column names
    normalized_df = pd.DataFrame(normalized_features, columns=feature_names)
    
    return normalized_df, scaler

def preprocess_data(file_path, label_column=None, scaler_type='standard'):
    """
    Complete preprocessing pipeline for network traffic data.
    
    Args:
        file_path (str): Path to the dataset file
        label_column (str, optional): Name of the label/target column
        scaler_type (str): Type of scaler to use ('standard', 'minmax')
        
    Returns:
        dict: Processed data including features, labels (if applicable), and scaler
    """
    logger.info(f"Starting preprocessing pipeline for {file_path}")
    
    # Load dataset
    df = load_dataset(file_path)
    
    # Clean data
    df_cleaned = clean_data(df)
    
    # Extract features and labels if applicable
    if label_column is not None:
        features, labels = extract_features(df_cleaned, label_column)
    else:
        features = extract_features(df_cleaned)
        labels = None
    
    # Normalize features
    normalized_features, scaler = normalize_features(features, scaler_type)
    
    result = {
        'features': normalized_features,
        'scaler': scaler
    }
    
    if labels is not None:
        result['labels'] = labels
    
    logger.info("Preprocessing completed successfully")
    return result

def download_datasets():
    """
    Download common IDS datasets for training and testing.
    Note: This function might require external dependencies like requests.
    """
    logger.info("Starting dataset download")
    
    # Create data directory if it doesn't exist
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    # Define datasets to download
    datasets = [
        {
            'name': 'CICIDS2017 Sample',
            'url': 'https://www.unb.ca/cic/datasets/ids-2017.html',
            'info': 'CICIDS2017 contains benign and attack traffic for various attack types.'
        },
        {
            'name': 'NSL-KDD Sample',
            'url': 'https://www.unb.ca/cic/datasets/nsl.html',
            'info': 'NSL-KDD is a modified version of the original KDD Cup 1999 dataset.'
        }
    ]
    
    # Print information about available datasets
    logger.info("The following datasets are available for download:")
    for i, dataset in enumerate(datasets):
        logger.info(f"{i+1}. {dataset['name']}: {dataset['info']}")
        logger.info(f"   URL: {dataset['url']}")
    
    logger.info("Please visit the URLs to download the datasets manually.")
    logger.info(f"Place the downloaded datasets in the {data_dir} directory.")
    
    return datasets

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    download_datasets() 