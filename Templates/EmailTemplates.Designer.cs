﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Cosmos.EmailServices.Templates {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "17.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    public class EmailTemplates {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal EmailTemplates() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Cosmos.EmailServices.Templates.EmailTemplates", typeof(EmailTemplates).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;!DOCTYPE html PUBLIC &quot;-//W3C//DTD XHTML 1.0 Strict//EN&quot; &quot;http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd&quot;&gt;
        ///&lt;html&gt;
        ///&lt;head&gt;
        ///    &lt;!-- Compiled with Bootstrap Email version: 1.4.0 --&gt;
        ///    &lt;meta http-equiv=&quot;x-ua-compatible&quot; content=&quot;ie=edge&quot; /&gt;
        ///    &lt;meta name=&quot;x-apple-disable-message-reformatting&quot; /&gt;
        ///    &lt;meta name=&quot;viewport&quot; content=&quot;width=device-width, initial-scale=1&quot; /&gt;
        ///    &lt;meta name=&quot;format-detection&quot; content=&quot;telephone=no, date=no, address=no, email=no&quot; /&gt;
        ///    &lt;meta http-equiv=&quot;Content-Type&quot; con [rest of string was truncated]&quot;;.
        /// </summary>
        public static string GeneralInfo {
            get {
                return ResourceManager.GetString("GeneralInfo", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to {{Subject}}
        ///{{Subtitle}}
        ///From: {{WebsiteName}}
        ///
        ///{{Body}}
        ///
        ///-------------------------------------------------
        ///This email was generated by Cosmos CMS.
        ///
        ///Cosmos is powered by:
        ///
        ///Moonrise Software, LLC.
        ///10080 N Wolfe Road Suite 200
        ///Cupertino, CA 95014.
        /// </summary>
        public static string GeneralInfoTXT {
            get {
                return ResourceManager.GetString("GeneralInfoTXT", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;!DOCTYPE html PUBLIC &quot;-//W3C//DTD XHTML 1.0 Strict//EN&quot; &quot;http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd&quot;&gt;
        ///&lt;html&gt;
        ///&lt;head&gt;
        ///    &lt;!-- Compiled with Bootstrap Email version: 1.4.0 --&gt;
        ///    &lt;meta http-equiv=&quot;x-ua-compatible&quot; content=&quot;ie=edge&quot;&gt;
        ///    &lt;meta name=&quot;x-apple-disable-message-reformatting&quot;&gt;
        ///    &lt;meta name=&quot;viewport&quot; content=&quot;width=device-width, initial-scale=1&quot;&gt;
        ///    &lt;meta name=&quot;format-detection&quot; content=&quot;telephone=no, date=no, address=no, email=no&quot;&gt;
        ///    &lt;meta http-equiv=&quot;Content-Type&quot; content=&quot;te [rest of string was truncated]&quot;;.
        /// </summary>
        public static string NewAccountConfirmEmail {
            get {
                return ResourceManager.GetString("NewAccountConfirmEmail", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to New Account Email Confirmation
        /// 
        ///We recieved a new account request for website: {{WebsiteName}}.
        ///
        ///Copy and paste the link below into your web browser to enable your account and confirm your email address.
        ///
        ///{{CallbackUrl}}
        ///
        ///Keeping your account secure is our top priority.
        /// 
        ///If you did not make this request, do not open the link above and ignore this email.
        ///
        ///This email was generated by Cosmos CMS.
        /// 
        ///Cosmos is powered by:
        ///
        ///Moonrise Software, LLC.
        ///10080 N Wolfe Road Suite 200
        ///Cupertino, CA 950 [rest of string was truncated]&quot;;.
        /// </summary>
        public static string NewAccountConfirmEmailTXT {
            get {
                return ResourceManager.GetString("NewAccountConfirmEmailTXT", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;!DOCTYPE html PUBLIC &quot;-//W3C//DTD XHTML 1.0 Strict//EN&quot; &quot;http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd&quot;&gt;
        ///&lt;html&gt;
        ///&lt;head&gt;
        ///    &lt;!-- Compiled with Bootstrap Email version: 1.4.0 --&gt;
        ///    &lt;meta http-equiv=&quot;x-ua-compatible&quot; content=&quot;ie=edge&quot;&gt;
        ///    &lt;meta name=&quot;x-apple-disable-message-reformatting&quot;&gt;
        ///    &lt;meta name=&quot;viewport&quot; content=&quot;width=device-width, initial-scale=1&quot;&gt;
        ///    &lt;meta name=&quot;format-detection&quot; content=&quot;telephone=no, date=no, address=no, email=no&quot;&gt;
        ///    &lt;meta http-equiv=&quot;Content-Type&quot; content=&quot;te [rest of string was truncated]&quot;;.
        /// </summary>
        public static string ResetPasswordTemplate {
            get {
                return ResourceManager.GetString("ResetPasswordTemplate", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Password Reset Requested
        /// 
        ///We received a request to reset your password for website: {{WebsiteName}}.
        ///
        ///To reset your password, copy and paste this link in your web browser:
        ///
        ///{{CallbackUrl}}
        ///
        ///Keeping your account secure is our top priority.
        /// 
        ///If you did not request this reset do not click the button above and please contact your website administrator.
        ///
        ///This email was generated by Cosmos CMS.
        /// 
        ///Cosmos is powered by:
        ///
        ///Moonrise Software, LLC.
        ///10080 N Wolfe Road Suite 200
        ///Cupertino, CA 95014
        ///.
        /// </summary>
        public static string ResetPasswordTemplateTXT {
            get {
                return ResourceManager.GetString("ResetPasswordTemplateTXT", resourceCulture);
            }
        }
    }
}
