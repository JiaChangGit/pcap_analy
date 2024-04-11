import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
from matplotlib.cm import ScalarMappable
import numpy as np
ReadPath = "./INFO/trace.txt"
SaveFigPath = "./INFO/unique3D_scatter.png"

# 從txt檔案中讀取數據並轉換為DataFrame
data = pd.read_csv(ReadPath, sep=' ', header=None)
data.columns = ['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol']

# 計算具有相同"source ip, destination ip, source port, destination port, protocol"的數據數量
grouped = data.groupby(['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol']).size().reset_index(name='count')

# 建立一個新的DataFrame，包含需要用於繪圖的數據
plot_data = grouped[grouped['count'] > 10]  # 僅選擇出現次數大於10的數據
# 篩選出count大於1000的數據
high_count_data = plot_data[plot_data['count'] > 1000]

# 歸一化數量以進行顏色對映
norm = Normalize(vmin=np.log2(plot_data['count'].min()), vmax=np.log2(plot_data['count'].max()))
# 選擇紅色調色板，顏色由淺到深
cmap = plt.get_cmap('Reds')
mappable = ScalarMappable(norm=norm, cmap=cmap)
colors = mappable.to_rgba(plot_data['count'])

# 繪製三維散點圖
fig = plt.figure(figsize=(20, 10))
ax = fig.add_subplot(111, projection='3d')

# 設定散點的大小和顏色
size = 10
ax.scatter(plot_data['source_ip'], plot_data['destination_ip'], plot_data['source_port'], s=size, c=colors, alpha=0.6)

# 在圖上標記出count大於的點的數值
for i, row in high_count_data.iterrows():
    ax.text(row['source_ip'], row['destination_ip'], row['source_port'], str(row['count']), color='black', fontsize=16)

# 設定座標軸標籤
ax.set_xlabel('Source IP')
ax.set_ylabel('Destination IP')
ax.set_zlabel('Source Port')
# 設定軸顯示範圍
ax.set_xlim(plot_data['source_ip'].min(), plot_data['source_ip'].max())
ax.set_ylim(plot_data['destination_ip'].min(), plot_data['destination_ip'].max())
ax.set_zlim(plot_data['source_port'].min(), plot_data['source_port'].max())

# 新增顏色條
plt.colorbar(mappable, ax=ax, label='Count')

plt.title('Scatter Plot of unique trace num (lg)')
plt.savefig(SaveFigPath)
plt.show()
