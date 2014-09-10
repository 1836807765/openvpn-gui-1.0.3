/*
 *  OpenVPN-GUI -- A Windows GUI for OpenVPN.
 *
 *  Copyright (C) 2004 Mathias Sundman <mathias@nilings.se>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Parts of this sourcefile is taken from openvpnserv.c from the
 *  OpenVPN source, with approval from the author, James Yonan
 *  <jim@yonan.net>.
 */


#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "main.h"
#include "options.h"
#include "openvpn.h"
#include "scripts.h"
#include "openvpn-gui-res.h"
#include "passphrase.h"
#include "tray.h"

extern struct options o;
bool g_bSettingProxy = false;

/* Wait for a complete line (CR/LF) and return it.
 * Return values:
 *  1 - Successful. Line is available in *line.
 *  0 - Broken Pipe during ReadFile.
 * -1 - Other Error during ReadFile.
 * 
 * I'm really unhappy with this code! If anyone knows of an easier
 * way to convert the streaming data from ReadFile() into lines,
 * please let me know!
 */
int ReadLineFromStdOut(HANDLE hStdOut, int config, char *line)
{
  #define MAX_LINELEN 1024

      CHAR lpBuffer[MAX_LINELEN];
      static char lastline[MAX_CONFIGS][MAX_LINELEN];
      static int charsleft[MAX_CONFIGS];
      char tmpline[MAX_LINELEN];
      DWORD nBytesRead;
      DWORD nCharsWritten;
      char *p;
      unsigned int len, i;
      static int first_call = 1;
      extern HINSTANCE hInstance;

  if (first_call)
    {
      for (i=0; i < MAX_CONFIGS; i++)
        charsleft[i]=0;
      first_call = 0;
    }

  while (true)
    {
      if (charsleft[config])
        {
          /* Check for Passphrase prompt */
          CheckPrivateKeyPassphrasePrompt(lastline[config], config);

          /* Check for Username/Password Auth prompt */
          CheckAuthUsernamePrompt(lastline[config], config);
          CheckAuthPasswordPrompt(lastline[config]);

          p=strchr(lastline[config], '\n');
          if (p == NULL)
            {
              if (!ReadFile(hStdOut,lpBuffer,sizeof(lpBuffer) - strlen(lastline[config]) - 1,
                                              &nBytesRead,NULL) || !nBytesRead)
                {
                  if (GetLastError() == ERROR_BROKEN_PIPE)
                    return(0); // pipe done - normal exit path.
                  else
                    {
                      /* error reading from pipe */
                      ShowLocalizedMsg(GUI_NAME, ERR_READ_STDOUT_PIPE, "");
                      return(-1);
                    } 
                }
              lpBuffer[nBytesRead] = '\0';
              p=strchr(lpBuffer, '\n');
              if (p == NULL)
                {
                  strncat(lastline[config], lpBuffer, sizeof(lastline[config]) - strlen(lastline[config]) - 1);
                  if (strlen(lastline[config]) >= (MAX_LINELEN - 1))
                    {
                      strncpy(line, lastline[config], MAX_LINELEN);
                      charsleft[config]=0;
                      return(1);
                    }
                }
              else
                {
                  p[0] = '\0';
                  strncpy(line, lastline[config], MAX_LINELEN - 1);
                  strncat(line, lpBuffer, MAX_LINELEN - strlen(line));
                  if (line[strlen(line) - 1] == '\r') line[strlen(line) - 1] = '\0';
                  if (nBytesRead > (strlen(lpBuffer) + 1))
                    {
                      strncpy(lastline[config], p+1, sizeof(lastline[config]) - 1);
                      charsleft[config]=1;
                      return(1);
                    }
                  charsleft[config]=0;
                  return(1);
                }
            }
          else
            {
              len = strlen(lastline[config]);
              p[0] = '\0';
              strncpy(line, lastline[config], MAX_LINELEN - 1);
              if (line[strlen(line) - 1] == '\r') line[strlen(line) - 1] = '\0';
              if (len > (strlen(line) + 2))
                {
                  strncpy(tmpline, p+1, sizeof(tmpline) - 1);
                  strncpy(lastline[config], tmpline, sizeof(lastline[config]) - 1);
                  charsleft[config]=1;
                  return(1);
                }
              charsleft[config]=0;
              return(1);
            }
        }
      else
        {  
          if (!ReadFile(hStdOut,lpBuffer,sizeof(lpBuffer) - 1,
                                          &nBytesRead,NULL) || !nBytesRead)
            {
              if (GetLastError() == ERROR_BROKEN_PIPE)
                return(0); // pipe done - normal exit path.
              else
                {
                  /* error reading from pipe */
                  ShowLocalizedMsg(GUI_NAME, ERR_READ_STDOUT_PIPE, "");
                  return(-1);
                } 
            }
          lpBuffer[nBytesRead] = '\0';
          p=strchr(lpBuffer, '\n');
          if (p == NULL)
            {
              if (nBytesRead >= (MAX_LINELEN - 1))
                {
                  strncpy(line, lpBuffer, MAX_LINELEN);
                  charsleft[config]=0;
                  return(1);
                }
              else
                {
                  strncpy(lastline[config], lpBuffer, sizeof(lastline[config]) - 1);
                  charsleft[config]=1;
                }
            }
          else
            {
              p[0] = '\0';
              strncpy(line, lpBuffer, MAX_LINELEN - 1);
              if (line[strlen(line) - 1] == '\r') line[strlen(line) - 1] = '\0';
              if (nBytesRead > strlen(line))
                {
                  strncpy(lastline[config], p+1, sizeof(lastline[config]) - 1);
                  charsleft[config]=1;
                  return(1);
                }
            }
        }     
    }
}

/*
 * 读取config的设置
 * add by mey 20131008
*/
void read_m_param(char* proxy_server, char* proxy_auto)
{
  LONG status;
  HKEY regkey;

  /* Open Registry for reading */
  status = RegOpenKeyEx(HKEY_CURRENT_USER,
                       "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                       0,
                       KEY_READ,
                       &regkey);

  /* Return if can't open the registry key */
  if (status != ERROR_SUCCESS) return;      

  /* get registry settings */
  GetRegistryValue(regkey, "m_proxy_server", proxy_server, 
                   100);
 
  GetRegistryValue(regkey, "m_proxy_auto_setting", proxy_auto, 
                   20);  

  RegCloseKey(regkey);
  return;  
}
/*
 * 修改注册表，修改局域网IE代理服务器IP地址
 * add by mey 20131008
*/
void modify_local_network_proxy(char* proxy_server, int proxy_enable)
{
	HKEY regkey;
	DWORD dwDispos;	

	/* Open Registry for writing */
  if (RegCreateKeyEx(HKEY_CURRENT_USER,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                    0,
                    (LPTSTR) "",
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &regkey,
                    &dwDispos) != ERROR_SUCCESS)
    {
      /* error creating Registry-Key */
      ShowLocalizedMsg(GUI_NAME, ERR_CREATE_REG_HKCU_KEY, GUI_REGKEY_HKCU);
      return;
    }

  /* Save Settings to registry */
  if(proxy_server != NULL)
  	SetRegistryValue(regkey, "ProxyServer", proxy_server);  

	SetRegistryValue_DWORD(regkey, "ProxyEnable", proxy_enable);

  RegCloseKey(regkey);	
}

void modify_adsl_network_proxy(char* key_name, char* proxy_server, int proxy_enable)
{
	if(key_name == NULL)
	{
		return;
	}
	
	HKEY regkey;
	DWORD dwDispos;	
	char pData[256];
	memset(pData, 0, 256);
	int nLen = 0;
	int newLen = 0;
 	int oldLen = 0;

	/* Open Registry for writing */
  if (RegCreateKeyEx(HKEY_CURRENT_USER,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections",
                    0,
                    (LPTSTR) "",
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &regkey,
                    &dwDispos) != ERROR_SUCCESS)
    {
      /* error creating Registry-Key */
      ShowLocalizedMsg(GUI_NAME, ERR_CREATE_REG_HKCU_KEY, GUI_REGKEY_HKCU);
      return;
    }
    
  nLen = GetRegistryValue_binary(regkey, key_name, pData, 256);
  if(proxy_enable == 0)
  	pData[8] = 1;//不启用
  else
  	pData[8] = 3;//启用
  if(NULL != proxy_server)
  {  	
  	newLen = strlen(proxy_server);
  	oldLen = pData[12];
  	if(oldLen != newLen)
  	{
  		memcpy(&pData[16+newLen], &pData[16+oldLen], nLen-16-oldLen-1);
  		nLen = nLen - oldLen + newLen;
  	} 
  	
  	memcpy(&pData[0x10], proxy_server, strlen(proxy_server)); 
  	pData[12] = strlen(proxy_server); 	
  }

  /* Save Settings to registry */ 
	SetRegistryValue_binary(regkey, key_name, pData, nLen);

  RegCloseKey(regkey);	
}

/*
 * 修改注册表，修改拨号网络IE代理服务器IP地址
 * add by mey 20131008
*/
void enum_adsl_network_proxy(char* proxy_server, int proxy_enable)
{
	HKEY regkey;
	DWORD dwDispos;
	int i = 0;
	long lResult;

	/* Open Registry for writing */
  if (RegCreateKeyEx(HKEY_CURRENT_USER,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections",
                    0,
                    (LPTSTR) "",
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS ,
                    NULL,
                    &regkey,
                    &dwDispos) != ERROR_SUCCESS)
    {
      /* error creating Registry-Key */
      ShowLocalizedMsg(GUI_NAME, ERR_CREATE_REG_HKCU_KEY, GUI_REGKEY_HKCU);
      //MessageBox(NULL, "1", "1", MB_OK);
      return;
    }
    
    for (i = 0; ;i++) //中間為空,沒有進行i值的比較
		{
	    char szValueName[256];
			memset(szValueName, 0, 256);
	    DWORD dwValueName = 256;
	    DWORD dwValueType;	
	    DWORD lResult;

 			lResult = RegEnumValue(regkey,i,szValueName,&dwValueName,
	              NULL,&dwValueType,NULL,NULL);
	    if (lResult != ERROR_SUCCESS) //通過此項退出循環
	    {
	         //if (lResult != ERROR_NO_MORE_ITEMS) bResult = FALSE;
	         //MessageBox(NULL, "2", "2", MB_OK);
	         break;
	    }
	    szValueName[dwValueName] = '\0';
	    if (strcmp(szValueName, "DefaultConnectionSettings") == 0 || \
	    		strcmp(szValueName, "SavedLegacySettings") == 0 )
	    {
	    	continue;
	    }
	    
	    modify_adsl_network_proxy(szValueName, proxy_server, proxy_enable);
		}

		RegCloseKey(regkey);	
}

/*
 * 修改注册表，修改IE代理服务器IP地址
 * add by mey 20131008
*/
void modify_ie_proxy_setting_while_close()
{
	if(false == g_bSettingProxy)
		return;
	HKEY regkey;
	DWORD dwDispos;
	char proxy_server[100] = "0";
	char proxy_auto[20] = "off";
	
	/*读取配置数据*/
	read_m_param(proxy_server, proxy_auto);
	
	if (strcmp(proxy_auto, "off") == 0)
	{
		return;
	}
  
  //
  if (strcmp(proxy_auto, "on") == 0)	
  {
  	//修改局域网下代理设置
  	modify_local_network_proxy(NULL, 0);	
  	//修改拨号下代理设置
  	enum_adsl_network_proxy(NULL, 0);	
  }				
  
  g_bSettingProxy = false;
}

/*
 * 修改注册表，修改IE代理服务器IP地址
 * add by mey 20131008
*/
void modify_ie_proxy_setting_while_connected()
{
	g_bSettingProxy = true;
	
	HKEY regkey;
	DWORD dwDispos;
	char proxy_server[100] = "0";
	char proxy_auto[20] = "off";
	
	/*读取配置数据*/
	read_m_param(proxy_server, proxy_auto);
	
	if (strcmp(proxy_auto, "off") == 0)
	{
		return;
	}


  if (strcmp(proxy_auto, "off") == 0)	
  {
  	//修改局域网下代理设置
  	modify_local_network_proxy(proxy_server, 0);	
  	//修改拨号下代理设置
  	enum_adsl_network_proxy(proxy_server, 0);	
  }	
  else
  {
  	//修改局域网下代理设置
  	modify_local_network_proxy(proxy_server, 1);	
  	//修改拨号下代理设置
  	enum_adsl_network_proxy(proxy_server, 1);	  	
  }

}


/*
 *  Monitor the openvpn log output while CONNECTING
 */
void monitor_openvpnlog_while_connecting(int config, char *line)
{
  TCHAR buf[1000];
  char msg[200];
  char msg2[200];
  unsigned int i;
  char *linepos;

  /* Check for Connected message */
  if (strstr(line, o.connect_string) != NULL)
    {
      /* Run Connect Script */
      RunConnectScript(config, false);

      /* Save time when we got connected. */
      o.cnn[config].connected_since = time(NULL);

      o.cnn[config].connect_status = CONNECTED;
      SetMenuStatus(config, CONNECTED);
      SetTrayIcon(CONNECTED);
      
      /*add by mey 20131008 start修改代理服务器配置*/
      modify_ie_proxy_setting_while_connected();
			/*add by mey 20131008 end修改代理服务器配置*/
			
      /* Remove Proxy Auth file */
      DeleteFile(o.proxy_authfile);

      /* Zero psw attempt counter */
      o.cnn[config].failed_psw_attempts = 0;

      /* UserInfo: Connected */
      myLoadString(INFO_STATE_CONNECTED);
      SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 
      SetStatusWinIcon(o.cnn[config].hwndStatus, APP_ICON_CONNECTED);

      /* Show Tray Balloon msg */
      if (o.show_balloon[0] != '0')
        {
          myLoadString(INFO_NOW_CONNECTED);
          mysnprintf(msg, buf, o.cnn[config].config_name);
          if (strlen(o.cnn[config].ip) > 0)
            {
              myLoadString(INFO_ASSIG_IP);
              mysnprintf(msg2, buf, o.cnn[config].ip);
            }
          else
            {
              mysnprintf(msg2," ");
            }
          ShowTrayBalloon(msg, msg2);
        }

      /* Hide Status Window */
      ShowWindow(o.cnn[config].hwndStatus, SW_HIDE);
    }

  /* Check for failed passphrase log message */
  if ((strstr(line, "TLS Error: Need PEM pass phrase for private key") != NULL) ||
       (strstr(line, "EVP_DecryptFinal:bad decrypt") != NULL) ||
       (strstr(line, "PKCS12_parse:mac verify failure") != NULL) ||
       (strstr(line, "Received AUTH_FAILED control message") != NULL) ||
       (strstr(line, "Auth username is empty") != NULL))
    {
      o.cnn[config].failed_psw_attempts++;
      o.cnn[config].failed_psw=1;
      o.cnn[config].restart=true;
    }

  /* Check for "certificate has expired" message */
  if ((strstr(line, "error=certificate has expired") != NULL))
    {
      StopOpenVPN(config);
      /* Cert expired... */
      ShowLocalizedMsg(GUI_NAME, ERR_CERT_EXPIRED, "");
    }

  /* Check for "certificate is not yet valid" message */
  if ((strstr(line, "error=certificate is not yet valid") != NULL))
    {
      StopOpenVPN(config);
      /* Cert not yet valid */
      ShowLocalizedMsg(GUI_NAME, ERR_CERT_NOT_YET_VALID, ""); 
    }

  /* Check for "Notified TAP-Win32 driver to set a DHCP IP" message */
  if (((linepos=strstr(line, "Notified TAP-Win32 driver to set a DHCP IP")) != NULL))
    {
      strncpy(o.cnn[config].ip, linepos+54, 15); /* Copy IP address */
      for (i=0; i < strlen(o.cnn[config].ip); i++)
        if (o.cnn[config].ip[i] == '/' || o.cnn[config].ip[i] == ' ') break;
      o.cnn[config].ip[i] = '\0';
    }
}


/*
 *  Monitor the openvpn log output while CONNECTED
 */
void monitor_openvpnlog_while_connected(int config, char *line)
{
  TCHAR buf[1000];

  /* Check for Ping-Restart message */
  if (strstr(line, "process restarting") != NULL)
    {
      /* Set connect_status = ReConnecting */
      o.cnn[config].connect_status = RECONNECTING;
      CheckAndSetTrayIcon();

      /* Set Status Window Controls "ReConnecting" */
      myLoadString(INFO_STATE_RECONNECTING);
      SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 
      SetStatusWinIcon(o.cnn[config].hwndStatus, APP_ICON_CONNECTING);
    }
}

/*
 *  Monitor the openvpn log output while RECONNECTING
 */
void monitor_openvpnlog_while_reconnecting(int config, char *line)
{
  TCHAR buf[1000];
  char msg[200];
  char msg2[200];
  unsigned int i;
  char *linepos;
  
  /* Check for Connected message */
  if (strstr(line, o.connect_string) != NULL)
    {
      o.cnn[config].connect_status = CONNECTED;
      SetTrayIcon(CONNECTED);

      /* Set Status Window Controls "Connected" */
      myLoadString(INFO_STATE_CONNECTED);
      SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 
      SetStatusWinIcon(o.cnn[config].hwndStatus, APP_ICON_CONNECTED);

      /* Show Tray Balloon msg */
      if (o.show_balloon[0] == '2')
        {
          myLoadString(INFO_NOW_CONNECTED);
          mysnprintf(msg, buf, o.cnn[config].config_name);
          if (strlen(o.cnn[config].ip) > 0)
            {
              myLoadString(INFO_ASSIG_IP);
              mysnprintf(msg2, buf, o.cnn[config].ip);
            }
          else
            {
              mysnprintf(msg2," ");
            }
          ShowTrayBalloon(msg, msg2);
        }
    }

  /* Check for failed passphrase log message */
  if ((strstr(line, "TLS Error: Need PEM pass phrase for private key") != NULL) ||
       (strstr(line, "EVP_DecryptFinal:bad decrypt") != NULL) ||
       (strstr(line, "PKCS12_parse:mac verify failure") != NULL) ||
       (strstr(line, "Received AUTH_FAILED control message") != NULL) ||
       (strstr(line, "Auth username is empty") != NULL))
    {
      o.cnn[config].failed_psw_attempts++;
      o.cnn[config].failed_psw=1;
      o.cnn[config].restart=true;
    }

  /* Check for "certificate has expired" message */
  if ((strstr(line, "error=certificate has expired") != NULL))
    {
      /* Cert expired */
      StopOpenVPN(config);
      ShowLocalizedMsg(GUI_NAME, ERR_CERT_EXPIRED, "");
    }

  /* Check for "certificate is not yet valid" message */
  if ((strstr(line, "error=certificate is not yet valid") != NULL))
    {
      StopOpenVPN(config);
      /* Cert not yet valid */
      ShowLocalizedMsg(GUI_NAME, ERR_CERT_NOT_YET_VALID, "");
    }

  /* Check for "Notified TAP-Win32 driver to set a DHCP IP" message */
  if (((linepos=strstr(line, "Notified TAP-Win32 driver to set a DHCP IP")) != NULL))
    {
      strncpy(o.cnn[config].ip, linepos+54, 15); /* Copy IP address */
      for (i=0; i < strlen(o.cnn[config].ip); i++)
        if (o.cnn[config].ip[i] == '/' || o.cnn[config].ip[i] == ' ') break;
      o.cnn[config].ip[i] = '\0';
    }
}

/*
 *add by mey 20131106
 *转换从管道中收到的日志，将部分翻译成中文用以显示
 */
void TransforLineToDisplay(char* srcLine, char* dstLine)
{
	static int nCount = 0;
	
	if(strstr(srcLine, "NOTE: debug verbosity (--verb 9) is enabled but this build lacks debug support") != NULL)
	{
		strcat(dstLine, "开始建立连接...\r\n");
	}
	else if(strstr(srcLine, "Cannot load certificate") != NULL)
	{
		strcat(dstLine, "未能正确载入证书，请检查...\r\n");
	}
	else if(strstr(srcLine, "Exiting due to fatal error") != NULL)
	{
		strcat(dstLine, "连接过程发生错误，准备退出！\r\n");
	}
	else if(strstr(srcLine, "will try again in 5 seconds: Connection refused") != NULL)
	{
		strcat(dstLine, "连接到服务器失败，5s后再次尝试！\r\n");
	}
	else if(strstr(srcLine, "There are no TAP-Win32 adapters on this system") != NULL)
	{
		strcat(dstLine, "未安装驱动程序，请检查！\r\n");		
	}
	else if(strstr(srcLine, "as a OpenVPN static key file") != NULL)
	{
		nCount = 0;
		strcat(dstLine, "准备连接服务器...\r\n");			
	}
	else if(strstr(srcLine, "Initialization Sequence Completed") != NULL)
	{
		strcat(dstLine, "初始化完成。\r\n");		
	}
	else if(strstr(srcLine, "'PUSH_REQUEST' (status=1)") != NULL)
	{		
		nCount++;
		if(nCount >= 2)
		{
			nCount = 0;
			strcat(dstLine, "用户已被禁止访问！\r\n");	
		}	
	}
	else if(strstr(srcLine, "SIGUSR1[soft,connection-reset] received") != NULL)
	{		
		strcat(dstLine, "服务器未识别此用户，可能已被吊销！\r\n");	
	}
	else if(strstr(srcLine, "PUSH: Received control message: 'PUSH_REPLY,") != NULL)
	{
		/*
		Tue Nov 12 18:19:26 2013 PUSH: Received control message: 'PUSH_REPLY,route 192.168.4.0 255.255.255.0,route 192.168.6.0 255.255.255.0,dhcp-option DOMAIN domain.com,route 10.8.0.0 255.255.255.0,topology net30,ping 10,ping-restart 60,ifconfig 10.8.0.26 10.8.0.25'
		*/
		int nPos = 0;
		char* pHead = srcLine;
		char* pc = NULL;
		char* p_ = NULL;//逗号
		char* p_m = NULL;
		char tmplst[32];		
		char iplst[256];
		memset(iplst, 0, 256);
		
		p_m = strstr(pHead, "dhcp-option DOMAIN");
		if(p_m == NULL)
			return;
		
		while(strstr(pHead, "route") != NULL)
		{
			memset(tmplst, 0, 32);
			pc = strstr(pHead, "route");
			if(pc > p_m)			
				break;			
			pc = pc + 5;//删除“route”
			
			p_ = strstr(pc, ",");
			if(p_ == NULL) return;			
			memcpy(tmplst, pc, p_-pc);
			strcat(iplst, "\r\n");	
			strcat(iplst, tmplst);	
			pHead = p_ + 1;						
		}		
		
		strcat(dstLine, "可用网段及掩码：");
		strcat(dstLine, iplst);
		strcat(dstLine, "\r\n");	
	}
}

/*
 * Opens a log file and monitors the started OpenVPN process.
 * All output from OpenVPN is written both to the logfile and
 * to the status window.
 *
 * The output from OpenVPN is also watch for diffrent messages
 * and appropriate actions are taken.
 */
void WatchOpenVPNProcess(int config)
{
  char line[1024];
  char trans_line[1024];//add by mey 20131106 经过翻译后的注释
  int ret;
  char filemode[2] = "w\0";
  FILE *fd;
  char msg[200];
  char msg2[200];
  int i;
  int iLineCount;
  int LogLines = 0;
  int logpos;
  char *linepos;
  HWND LogWindow;
  TCHAR buf[1000];

  /* set log file append/truncate filemode */
  if (o.append_string[0] == '1')
    filemode[0] = 'a';

  /* Set Connect_Status = "Connecting" */
  o.cnn[config].connect_status = CONNECTING;
 
  /* Set Tray Icon = "Connecting" if no other connections are running */
  CheckAndSetTrayIcon();

  /* Set MenuStatus = "Connecting" */
  SetMenuStatus(config, CONNECTING);
  
  /* Clear failed_password flag */
  o.cnn[config].failed_psw = 0;

  /* Open log file */
  if ((fd=fopen(o.cnn[config].log_path, filemode)) == NULL)
    ShowLocalizedMsg (GUI_NAME, ERR_OPEN_LOG_WRITE, o.cnn[config].log_path);

  LogWindow = GetDlgItem(o.cnn[config].hwndStatus, EDIT_LOG);
  //modify by mey start 20130904 隐藏log显示
  ShowWindow(LogWindow, SW_SHOW);
  //modify by mey end
  while(TRUE)
    {
      if ((ret=ReadLineFromStdOut(o.cnn[config].hStdOut, config, line)) == 1)
        {

          /* Do nothing if line length = 0 */
          if (strlen(line) == 0) continue;

          /* Write line to Log file */
          if (fd != NULL)
            {
              fputs (line, fd);
              fputc ('\n', fd);
              fflush (fd);
            }

          /* Remove lines from LogWindow if it is getting full */
          LogLines++;
          if (LogLines > MAX_LOG_LINES)
            {
              logpos = SendMessage(LogWindow, EM_LINEINDEX, DEL_LOG_LINES, 0);
              SendMessage(LogWindow, EM_SETSEL, 0, logpos);
              SendMessage(LogWindow, EM_REPLACESEL, FALSE, (LPARAM) "");
              LogLines -= DEL_LOG_LINES;
         }

          /* Write line to LogWindow */
          /*//del by mey start 20131106删除原有的显示日志，将其转化
          strcat(line, "\r\n");
          SendMessage(LogWindow, EM_SETSEL, (WPARAM) -1, (LPARAM) -1);
          SendMessage(LogWindow, EM_REPLACESEL, FALSE, (LPARAM) line);
          */
          //del by mey end 20131106
          //add by mey 20131106 start
          memset(trans_line, 0, 1024);
          TransforLineToDisplay(line, trans_line);
          if(trans_line[0] != 0)
          {
         		SendMessage(LogWindow, EM_SETSEL, (WPARAM) -1, (LPARAM) -1);
          	SendMessage(LogWindow, EM_REPLACESEL, FALSE, (LPARAM) trans_line);          	
          } 
          //add by mey 20131106 end

          if (o.cnn[config].connect_status == CONNECTING) /* Connecting state */
            monitor_openvpnlog_while_connecting(config, line);

          if (o.cnn[config].connect_status == CONNECTED) /* Connected state */
            monitor_openvpnlog_while_connected(config, line);

          if (o.cnn[config].connect_status == RECONNECTING) /* ReConnecting state */
            monitor_openvpnlog_while_reconnecting(config, line);
        }
      else break;

    }


  /* OpenVPN has been shutdown */
 
  /* Close logfile filedesc. */
  if (fd != NULL) fclose(fd);

  /* Close StdIn/StdOut handles */
  CloseHandle(o.cnn[config].hStdIn);
  CloseHandle(o.cnn[config].hStdOut);

  /* Close exitevent handle */
  CloseHandle(o.cnn[config].exit_event);
  o.cnn[config].exit_event = NULL;    

  /* Enable/Disable menuitems for this connections */
  SetMenuStatus(config, DISCONNECTING);

  /* Remove Proxy Auth file */
  DeleteFile(o.proxy_authfile);

  /* Process died outside our control */
  if(o.cnn[config].connect_status == CONNECTED)		
    {
      /* Zero psw attempt counter */
      o.cnn[config].failed_psw_attempts = 0;

      /* Set connect_status = "Not Connected" */
      o.cnn[config].connect_status=DISCONNECTED;

      /* Change tray icon if no more connections is running */
      CheckAndSetTrayIcon();

      /* Show Status Window */
      myLoadString(INFO_STATE_DISCONNECTED);
      SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf);       
      SetStatusWinIcon(o.cnn[config].hwndStatus, APP_ICON_DISCONNECTED);
      EnableWindow(GetDlgItem(o.cnn[config].hwndStatus, ID_DISCONNECT), FALSE);
      EnableWindow(GetDlgItem(o.cnn[config].hwndStatus, ID_RESTART), FALSE);
      SetForegroundWindow(o.cnn[config].hwndStatus);
      ShowWindow(o.cnn[config].hwndStatus, SW_SHOW);
      ShowLocalizedMsg(GUI_NAME, INFO_CONN_TERMINATED, o.cnn[config].config_name); 

      /* Close Status Window */
      SendMessage(o.cnn[config].hwndStatus, WM_CLOSE, 0, 0);
    }

  /* We have failed to connect */
  else if(o.cnn[config].connect_status == CONNECTING)	
    {

      /* Set connect_status = "DisConnecting" */
      o.cnn[config].connect_status=DISCONNECTING;

      /* Change tray icon if no more connections is running */
      CheckAndSetTrayIcon();

      if ((o.cnn[config].failed_psw) && 
          (o.cnn[config].failed_psw_attempts < o.psw_attempts))
        {
          /* Restart OpenVPN to make another attempt to connect */
          PostMessage(o.hWnd, WM_COMMAND, (WPARAM) IDM_CONNECTMENU + config, 0);
        }
      else
        {
          /* Show Status Window */
          myLoadString(INFO_STATE_FAILED);
          SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 
          SetStatusWinIcon(o.cnn[config].hwndStatus, APP_ICON_DISCONNECTED);
          EnableWindow(GetDlgItem(o.cnn[config].hwndStatus, ID_DISCONNECT), FALSE);
          EnableWindow(GetDlgItem(o.cnn[config].hwndStatus, ID_RESTART), FALSE);
          SetForegroundWindow(o.cnn[config].hwndStatus);
          ShowWindow(o.cnn[config].hwndStatus, SW_SHOW);

          /* Zero psw attempt counter */
          o.cnn[config].failed_psw_attempts = 0;

	//add by andy start ,use TrayBalloon replace MsgBox
          //ShowLocalizedMsg(GUI_NAME, INFO_CONN_FAILED, o.cnn[config].config_name);
	  char msga1[200] = {"证书变化或使用了新key"};
	  char msga2[200] = {"请重新选择证书连接"};
          ShowTrayBalloon(msga1, msga2);

	//add by andy end ,use TrayBalloon replace MsgBox
	
          /* Set connect_status = "Not Connected" */
          o.cnn[config].connect_status=DISCONNECTED;

          /* Close Status Window */
          SendMessage(o.cnn[config].hwndStatus, WM_CLOSE, 0, 0);

          /* Reset restart flag */
          o.cnn[config].restart=false;

	  //add by andy ,start
	  //del Cert file
	  FILE *afp;
	  char aline[256];
	  char afile_path[MAX_PATH];
	  memset(afile_path, 0, MAX_PATH);
	   GetModuleFileName(NULL, afile_path, MAX_PATH);
	   char* ap = strrchr(afile_path, '//');
	   if(ap == NULL)
		   ap = strrchr(afile_path, '\\');
	   if(ap != NULL)
		   *ap=0x00;
	   strncat(afile_path, "\\m_key.txt", 10);
	  remove(afile_path);
  	//add by andy ,end

        }
    }

  /* We have failed to reconnect */
  else if(o.cnn[config].connect_status == RECONNECTING)	
    {

      /* Set connect_status = "DisConnecting" */
      o.cnn[config].connect_status=DISCONNECTING;

      /* Change tray icon if no more connections is running */
      CheckAndSetTrayIcon();

      if ((o.cnn[config].failed_psw) && 
          (o.cnn[config].failed_psw_attempts < o.psw_attempts))
        {
          /* Restart OpenVPN to make another attempt to connect */
          PostMessage(o.hWnd, WM_COMMAND, (WPARAM) IDM_CONNECTMENU + config, 0);
        }
      else
        {
          /* Show Status Window */
          myLoadString(INFO_STATE_FAILED_RECONN);
          SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 
          SetStatusWinIcon(o.cnn[config].hwndStatus, APP_ICON_DISCONNECTED);
          EnableWindow(GetDlgItem(o.cnn[config].hwndStatus, ID_DISCONNECT), FALSE);
          EnableWindow(GetDlgItem(o.cnn[config].hwndStatus, ID_RESTART), FALSE);
          SetForegroundWindow(o.cnn[config].hwndStatus);
          ShowWindow(o.cnn[config].hwndStatus, SW_SHOW);

          /* Zero psw attempt counter */
          o.cnn[config].failed_psw_attempts = 0;

          ShowLocalizedMsg(GUI_NAME, INFO_RECONN_FAILED, o.cnn[config].config_name);

          /* Set connect_status = "Not Connected" */
          o.cnn[config].connect_status=DISCONNECTED;

          /* Close Status Window */
          SendMessage(o.cnn[config].hwndStatus, WM_CLOSE, 0, 0);

          /* Reset restart flag */
          o.cnn[config].restart=false;
        }
    }

  /* We have chosed to Disconnect */
  else if(o.cnn[config].connect_status == DISCONNECTING)						
    {
      /* Zero psw attempt counter */
      o.cnn[config].failed_psw_attempts = 0;

      /* Set connect_status = "Not Connected" */
      o.cnn[config].connect_status=DISCONNECTED;

      /* Change tray icon if no more connections is running */
      CheckAndSetTrayIcon();

      if (o.cnn[config].restart)
        {
          /* Restart OpenVPN */
          StartOpenVPN(config);
        }
      else
        {
          /* Close Status Window */
          SendMessage(o.cnn[config].hwndStatus, WM_CLOSE, 0, 0);
        }
    }

  /* We have chosed to Suspend */
  else if(o.cnn[config].connect_status == SUSPENDING)						
    {
      /* Zero psw attempt counter */
      o.cnn[config].failed_psw_attempts = 0;

      /* Set connect_status = "SUSPENDED" */
      o.cnn[config].connect_status=SUSPENDED;
      myLoadString(INFO_STATE_SUSPENDED);
      SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 

      /* Change tray icon if no more connections is running */
      CheckAndSetTrayIcon();
    }

  /* Enable/Disable menuitems for this connections */
  SetMenuStatus(config, DISCONNECTED);
  
  //modify by mey 20131008 start
  if (o.cnn[config].connect_status == DISCONNECTED)
  	modify_ie_proxy_setting_while_close();
  //modify by mey 20131008 end

}

