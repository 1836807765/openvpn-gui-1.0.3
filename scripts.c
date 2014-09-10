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
 */

#include <windows.h>
//#include <stdlib.h>
//#include <stdio.h>
#include <process.h>
#include "main.h"
#include "openvpn-gui-res.h"
#include "options.h"

extern struct options o;

void RunConnectScript(int config, int run_as_service)
{
  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;
  STARTUPINFO start_info;
  PROCESS_INFORMATION proc_info;
  SECURITY_ATTRIBUTES sa;
  SECURITY_DESCRIPTOR sd;
  char command_line[256];
  char batch_file[100];
  DWORD ExitCode;
  int i, TimeOut;
  TCHAR buf[1000];

  /* Cut of extention from config filename and add "_up.bat". */
  strncpy(batch_file, o.cnn[config].config_file, sizeof(batch_file));
  batch_file[strlen(batch_file) - (strlen(o.ext_string)+1)]=0;
  strncat(batch_file, "_up.bat", sizeof(batch_file) - strlen(batch_file) - 1);
  mysnprintf(command_line, "%s\\%s", o.cnn[config].config_dir, batch_file);

  
  /* Return if no script exists */
  hFind = FindFirstFile(command_line, &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) 
  {
    return;
  }

  FindClose(hFind);

  if (!run_as_service)
    {
      /* UserInfo: Connect Script running */
      myLoadString(INFO_STATE_CONN_SCRIPT);
      SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 
    }

  CLEAR (start_info);
  CLEAR (proc_info);
  CLEAR (sa);
  CLEAR (sd);

  /* fill in STARTUPINFO struct */
  GetStartupInfo(&start_info);
  start_info.cb = sizeof(start_info);
  start_info.dwFlags = 0;
  start_info.wShowWindow = SW_SHOWDEFAULT;
  start_info.hStdInput = NULL;
  start_info.hStdOutput = NULL;

  if (!CreateProcess(NULL,
		     command_line, 	//commandline
		     NULL,
		     NULL,
		     TRUE,
		     ((o.show_script_window[0] == '1') ? (DWORD) CREATE_NEW_CONSOLE : 
                                                         (DWORD) CREATE_NO_WINDOW),
		     NULL,
		     o.cnn[config].config_dir,	//start-up dir
		     &start_info,
		     &proc_info))
    {
      /* Running Script failed */
      ShowLocalizedMsg(GUI_NAME, ERR_RUN_CONN_SCRIPT, command_line);
      return;
    }

  TimeOut = o.connectscript_timeout;

  if (TimeOut == 0)
    {
      /* Don't check exist status, just return */
      return;
    }

  for (i=0; i <= TimeOut; i++)
    {
      if (!GetExitCodeProcess(proc_info.hProcess, &ExitCode))
        {
          /* failed to get ExitCode */
          ShowLocalizedMsg(GUI_NAME, ERR_GET_EXIT_CODE, command_line);
          return;
        }

      if (ExitCode != STILL_ACTIVE)
        {
          if (ExitCode != 0)
            {
              /* ConnectScript failed */
              ShowLocalizedMsg(GUI_NAME, ERR_CONN_SCRIPT_FAILED, ExitCode);
              return;
            }
          return;
        }
    
      Sleep(1000);
    }    

  /* UserInfo: Timeout */
  ShowLocalizedMsg(GUI_NAME, ERR_RUN_CONN_SCRIPT_TIMEOUT, TimeOut);

}

void RunDisconnectScript(int config, int run_as_service)
{
  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;
  STARTUPINFO start_info;
  PROCESS_INFORMATION proc_info;
  SECURITY_ATTRIBUTES sa;
  SECURITY_DESCRIPTOR sd;
  char command_line[256];
  char batch_file[100];
  DWORD ExitCode;
  int i, TimeOut;
  TCHAR buf[1000];

  /* Append "_down.bat" to config name. */
  strncpy(batch_file, o.cnn[config].config_name, sizeof(batch_file));
  strncat(batch_file, "_down.bat", sizeof(batch_file) - strlen(batch_file) - 1);
  mysnprintf(command_line, "%s\\%s", o.cnn[config].config_dir, batch_file);

  
  /* Return if no script exists */
  hFind = FindFirstFile(command_line, &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) 
  {
    return;
  }

  FindClose(hFind);

  if (!run_as_service)
    {
      /* UserInfo: Disconnect Script running */
      myLoadString(INFO_STATE_DISCONN_SCRIPT);
      SetDlgItemText(o.cnn[config].hwndStatus, TEXT_STATUS, buf); 
    }

  CLEAR (start_info);
  CLEAR (proc_info);
  CLEAR (sa);
  CLEAR (sd);

  /* fill in STARTUPINFO struct */
  GetStartupInfo(&start_info);
  start_info.cb = sizeof(start_info);
  start_info.dwFlags = 0;
  start_info.wShowWindow = SW_SHOWDEFAULT;
  start_info.hStdInput = NULL;
  start_info.hStdOutput = NULL;

  if (!CreateProcess(NULL,
		     command_line, 	//commandline
		     NULL,
		     NULL,
		     TRUE,
		     ((o.show_script_window[0] == '1') ? (DWORD) CREATE_NEW_CONSOLE : 
                                                         (DWORD) CREATE_NO_WINDOW),
		     NULL,
		     o.cnn[config].config_dir,	//start-up dir
		     &start_info,
		     &proc_info))
    {
      return;
    }

  TimeOut = o.disconnectscript_timeout;

  for (i=0; i <= TimeOut; i++)
    {
      if (!GetExitCodeProcess(proc_info.hProcess, &ExitCode))
        {
          return;
        }

      if (ExitCode != STILL_ACTIVE)
        {
          return;
        }
    
      Sleep(1000);
    }    
}

void RunPreconnectScript(int config, char *return_string, int return_len)
{

  HANDLE hc_stdo_r = NULL;
  HANDLE hc_stdo_w = NULL;

  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;
  STARTUPINFO start_info;
  PROCESS_INFORMATION proc_info;
  SECURITY_ATTRIBUTES sa;
  SECURITY_DESCRIPTOR sd;
  char command_line[256];
  char batch_file[100];
  DWORD ExitCode;
  int i, TimeOut;
  TCHAR buf[1000];

  /* Append "_pre.bat" to config name. */
  strncpy(batch_file, o.cnn[config].config_name, sizeof(batch_file));
  strncat(batch_file, "_pre.bat", sizeof(batch_file) - strlen(batch_file) - 1);
  mysnprintf(command_line, "%s\\%s", o.cnn[config].config_dir, batch_file);

  
  /* Return if no script exists */
  hFind = FindFirstFile(command_line, &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) 
  {
    return;
  }

  FindClose(hFind);
  
  /* MSDN said:
       "If you are using a long file name that contains a space,
       use quoted strings to indicate where the file name ends
       and the arguments begin ..."
     so, change "%s\\%s" to "\"%s\\%s\""
  */
  mysnprintf(command_line, "\"%s\\%s\"", o.cnn[config].config_dir, batch_file);

  CLEAR (start_info);
  CLEAR (proc_info);
  CLEAR (sa);
  CLEAR (sd);

  sa.nLength = sizeof (sa);
  sa.lpSecurityDescriptor = &sd;
  sa.bInheritHandle = TRUE;
  if (!InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION))
    {
      goto failed;
    }
  if (!SetSecurityDescriptorDacl (&sd, TRUE, NULL, FALSE))
    {
      goto failed;
    }
  if (!CreatePipe(&hc_stdo_r,&hc_stdo_w,&sa,0))
    {
      goto failed;
    }
  if (!SetHandleInformation(hc_stdo_r, HANDLE_FLAG_INHERIT, 0) )
    {
      goto failed;
    }

  TimeOut = o.preconnectscript_timeout;

  if (return_string && return_len && return_string[0])
  	{
  		strncat(command_line, return_string, sizeof(command_line) - strlen(command_line) - 1);
  		memset(return_string, 0, (size_t)return_len);
      if (TimeOut < 150)
      	{
  	    	TimeOut = 150;
  	    }
  	}

  /* fill in STARTUPINFO struct */
  GetStartupInfo(&start_info);
  start_info.cb = sizeof(start_info);
  start_info.dwFlags = STARTF_USESTDHANDLES;
  start_info.wShowWindow = SW_SHOWDEFAULT;
  start_info.hStdInput = NULL;
  start_info.hStdOutput = hc_stdo_w;
  start_info.hStdError = NULL;

  if (!CreateProcess(NULL,
		     command_line, 	//commandline
		     NULL,
		     NULL,
		     TRUE,
		     ((o.show_script_window[0] == '1') ? (DWORD) CREATE_NEW_CONSOLE : 
                                                         (DWORD) CREATE_NO_WINDOW),
		     NULL,
		     o.cnn[config].config_dir,	//start-up dir
		     &start_info,
		     &proc_info))
    {
      goto failed;
    }

  for (i=0; i <= TimeOut; i++)
    {
      if (!GetExitCodeProcess(proc_info.hProcess, &ExitCode))
        {
          break;
        }

      if (ExitCode != STILL_ACTIVE)
        {
          break;
        }
    
      Sleep(1000);
    }
  if (CloseHandle(hc_stdo_w)&& return_string && return_len)
  	{
  		DWORD dwRead = 0;
      if (ReadFile(hc_stdo_r, return_string, (DWORD)return_len - 1, &dwRead, NULL))
      	{
      		while (dwRead)
      		  {
      		  	dwRead--;
      		  	if (return_string[dwRead] < ' ')
      		  		{
      		  			return_string[dwRead] = ' ';
      		  		}
      		  }
      	}
      hc_stdo_w = NULL;
  	}
failed:
	if (hc_stdo_w) CloseHandle(hc_stdo_w);
	if (hc_stdo_r) CloseHandle(hc_stdo_r);
  if (proc_info.hProcess) CloseHandle(proc_info.hProcess);
  if (proc_info.hThread) CloseHandle(proc_info.hThread);
	return;
}

