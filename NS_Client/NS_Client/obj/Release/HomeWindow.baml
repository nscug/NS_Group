   M S B A M L   `   `   `  ���� D  @NS_Client, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null%clr-namespace:NS_Client	NS_Client      NS_Client.HomeWindow   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     )localclr-namespace:NS_Client       � Title$  
HomeWindow��$	��450��$	��800��.���  � RowDefinitions �� $	��82* ��� $
��337* � � ColumnDefinitions �� �� �� .+��� -    ��Name$ textBox��$��2��$
��Left=�$��25��$��	27,35,0,0q� �� TextWrapping$
 Wrap=�$�� ��$	��Top=�$	��147���� -    ��Name$ image��$��/Search.png��$��1��$
��Left=�$��33��$��
263,35,0,0q�$	��Top=�$��51��$��2���� -    ��Name$ 	textBlock��$
��Left=�$��	70,18,0,0q�$
��Wrap=�$��Online Address Book��$��42(�$	��Top=�$��2��$��62��$	��433���� -    ��Name$ button��$��Search��$��2��$
��Left=�$��179,35,0,22q�$��75��&   System.Windows.Controls.DataGrid  -     Name$ dataGrid��$��3��$
��Left=�$	��334��$��0,3,0,0q�$	��Top=�$	��792��$��1��	   AlternatingRowBackground	 �� 
 �� EndPoint$
 0.5,1&� �� 
StartPoint$ 0.5,0&� �� RelativeTransform V� .~���  �� CenterY$	 0.5Q� �� CenterX$	 0.5Q���  �� CenterY$	 0.5Q� �� CenterX$	 0.5Q���  �� CenterY$	 0.5Q� �� CenterX$	 0.5Q� �� Angle$ 90Q�T� .���  � Color$ White�� � Offset$ 0Q�� $ 	#FF5BB0F7��$ 1Q�   Columns 0  *System.Windows.Controls.DataGridTextColumn  ,  &System.Windows.Controls.DataGridColumn   Header$
 Name��   Width5  /System.Windows.Controls.DataGridLengthConverter$	 200 1  +System.Windows.Controls.DataGridBoundColumn   Binding �� *Name+  $ Phone��$	 200  �� *Phone+  $
 Else��$	 200  �� *Else+4  .System.Windows.Controls.DataGridTemplateColumn  $ Button��$	 200    CellTemplate �� .R��� -   $��获取������ *Edit+