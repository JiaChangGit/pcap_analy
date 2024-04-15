import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
from matplotlib.cm import ScalarMappable

filePath = './INFO/loadTest.txt'
SaveFigPath = "./INFO/same3D_scatter.png"
SaveFigPath2 = "./INFO/plot5D.png"

def load_data_draw(filePath):
    data = np.loadtxt(filePath, skiprows=2, dtype=int)
    columns = ['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'count']
    df = pd.DataFrame(data, columns=columns)
    # 僅選擇出現次數大於10的數據
    plot_data = df[df['count'] > 10]

    # 篩選出count大於1000的數據
    high_count_data = plot_data[plot_data['count'] > 1000]

    # 歸一化數量以進行顏色對映
    norm = Normalize(vmin=np.log2(plot_data['count'].min()), vmax=np.log2(plot_data['count'].max()))
    # 選擇紅色調色板，顏色由淺到深
    cmap = plt.get_cmap('Reds')
    mappable = ScalarMappable(norm=norm, cmap=cmap)
    colors = mappable.to_rgba(plot_data['count'])

    # print(plot_data)
    fig = plt.figure(figsize=(20, 12))
    # 繪製三維散點圖
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
    ax.set_title('Scatter Plot of same trace num')
    # 新增顏色條
    plt.colorbar(mappable, ax=ax, label='Count')

    plt.savefig(SaveFigPath)
    plt.show()


    ### Plot
    fig = plt.figure(figsize=(20, 14))
    for i, col in enumerate(['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol']):
        ax = fig.add_subplot(5, 1, i+1)
        grouped = df.groupby(col)['count'].sum().reset_index(name='same')
        # 僅選擇出現次數大於200的數據
        plot_data = grouped[grouped['same'] > 200]
        ax.plot(plot_data[col], plot_data['same'], color='blue', marker='*')
        ax.set_xlabel(col)
        ax.set_ylabel('same')
        ax.set_xlim(plot_data[col].min(), plot_data[col].max())
        ax.set_ylim(plot_data['same'].min(), plot_data['same'].max())
        # highlight 次數大於10000的數據
        for x, y in zip(plot_data[col],plot_data['same']):
            if y>10000:
                s = f"{x:.2f}, {y}"
                ax.annotate(s,(x,y),textcoords="offset points",xytext=(0,18))

    ax.set_title('Plot of same x-ax')
    plt.tight_layout()
    plt.savefig(SaveFigPath2)
    plt.show()



def main():
    load_data_draw(filePath)


if __name__ == "__main__":
    main()
