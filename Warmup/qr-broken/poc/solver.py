import numpy as np
from PIL import Image
import zxingcpp

gray = np.array(Image.open("../release/broken.png").convert("L"))
result = zxingcpp.read_barcodes(gray)[0]
print(result.text)
# -> JCC{iph0n3_16_pr0_max_aku_b1sa_bac4_ini_kok}