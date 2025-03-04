# import re

# def extract_public_classes(file_path):
#     """
#     提取指定文件中所有public class的定义，并将每个类保存为以类名命名的文件。
#     """
#     # 用于匹配类定义的开始和结束
#     class_start_pattern = re.compile(r'\bpublic class (\w+)')
#     brace_pattern = re.compile(r'\{|\}')

#     with open(file_path, 'r') as file:
#         content = file.read()

#     # 找到所有大括号，以便确定类的开始和结束
#     braces = list(brace_pattern.finditer(content))

#     # 记录大括号的平衡状态以确定类的边界
#     brace_balance = 0
#     class_start = None
#     for match in class_start_pattern.finditer(content):
#         class_name = match.group(1)
#         class_content = []
#         for brace in braces:
#             if brace.start() >= match.start():
#                 if brace.group() == '{':
#                     brace_balance += 1
#                     if brace_balance == 1:  # 类定义开始
#                         class_start = brace.start()
#                 else:
#                     brace_balance -= 1
#                     if brace_balance == 0 and class_start is not None:  # 类定义结束
#                         class_content.append(content[class_start:brace.end()])
#                         class_start = None
#                         # 将类内容保存到文件
#                         with open(f"{class_name}.java", 'w') as class_file:
#                             class_file.write(''.join(class_content))
#                         break  # 退出循环，开始寻找下一个类定义

# if __name__ == "__main__":
#     # 替换这里的文件路径为实际Java文件的路径
#     java_file_path = 'data1.txt'
#     extract_public_classes(java_file_path)

import re
import os

def extract_java_code_blocks(file_path,folder_name):
    """
    提取文本文件中所有以```java标记的Java代码块，并根据其中的public class定义保存到相应的文件。
    """
    java_code_block_pattern = re.compile(r'```java(.*?)```', re.DOTALL)
    class_name_pattern = re.compile(r'public class (\w+)')

    with open(file_path, 'r') as file:
        content = file.read()

    java_code_blocks = java_code_block_pattern.findall(content)

    for block in java_code_blocks:
        class_name_search = class_name_pattern.search(block)
        if class_name_search:
            class_name = class_name_search.group(1)
            os.makedirs(f"{folder_name}/{class_name[:-1]}", exist_ok=True)

            with open(f"{folder_name}/{class_name[:-1]}/{class_name}.java", 'w') as class_file:
                # 移除代码块中可能的开头和结尾的空白字符
                class_file.write(block.strip())

if __name__ == "__main__":
    # 替换这里的文件路径为你的文本文件路径
    # txt_file_path = 'gpt_error.txt'
    # 接受两个输入的参数，一个为文件路径，一个为文件夹名字
    import sys
    txt_file_path = sys.argv[1]
    folder_name = sys.argv[2]
    extract_java_code_blocks(txt_file_path, folder_name)



