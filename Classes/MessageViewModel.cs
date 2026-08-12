using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace VirusScan2.Classes
{
    public class MessageViewModel
    {
        public string Message { get; set; }
        public string Title { get; set; }

        public MessageViewModel(string message, string title)
        {
            Message = message;
            Title = title;
        }
    }
}
