import cv2
import numpy as np

def load_image(image_path):
    """
    Load an image from a file path
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        numpy.ndarray: The loaded image
    """
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Could not load image from {image_path}")
    return img

def preprocess_image(img):
    """
    Preprocess the image for license plate detection
    
    Args:
        img (numpy.ndarray): Input image
        
    Returns:
        tuple: Original image and preprocessed image (edges)
    """
    # Convert to grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # Apply Gaussian blur to reduce noise
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    
    # Apply Canny edge detection
    edges = cv2.Canny(blur, 100, 200)
    
    return img, edges

def apply_threshold(img):
    """
    Apply thresholding to the image for better OCR results
    
    Args:
        img (numpy.ndarray): Input grayscale image
        
    Returns:
        numpy.ndarray: Thresholded image
    """
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if len(img.shape) == 3 else img
    _, binary = cv2.threshold(gray, 100, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return binary

def enhance_plate_image(plate_img):
    """
    Enhance the license plate image for better OCR results
    
    Args:
        plate_img (numpy.ndarray): Cropped license plate image
        
    Returns:
        numpy.ndarray: Enhanced license plate image
    """
    # Convert to grayscale if not already
    gray = cv2.cvtColor(plate_img, cv2.COLOR_BGR2GRAY) if len(plate_img.shape) == 3 else plate_img
    
    # Apply bilateral filter to reduce noise while keeping edges sharp
    denoised = cv2.bilateralFilter(gray, 11, 17, 17)
    
    # Apply adaptive thresholding
    thresh = cv2.adaptiveThreshold(denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                   cv2.THRESH_BINARY, 11, 2)
    
    # Morphological operations to further clean up the image
    kernel = np.ones((1, 1), np.uint8)
    opening = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel)
    
    return opening

if __name__ == "__main__":
    # Test the preprocessing functions
    import sys
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        try:
            img = load_image(image_path)
            original, edges = preprocess_image(img)
            
            # Display results
            cv2.imshow("Original", original)
            cv2.imshow("Edges", edges)
            cv2.waitKey(0)
            cv2.destroyAllWindows()
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Please provide an image path as a command line argument.") 