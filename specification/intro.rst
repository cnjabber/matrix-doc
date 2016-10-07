.. Copyright 2016 OpenMarket Ltd
..
.. Licensed under the Apache License, Version 2.0 (the "License");
.. you may not use this file except in compliance with the License.
.. You may obtain a copy of the License at
..
..     http://www.apache.org/licenses/LICENSE-2.0
..
.. Unless required by applicable law or agreed to in writing, software
.. distributed under the License is distributed on an "AS IS" BASIS,
.. WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
.. See the License for the specific language governing permissions and
.. limitations under the License.

.. contents:: Table of Contents
.. sectnum::

.. Note that this file is specifically unversioned because we don't want to
.. have to add Yet Another version number, and the commentary on what specs we
.. have should hopefully not get complex enough that we need to worry about
.. versioning it.

前言
------------
.. WARNING::
  Matrix 的规范还在演化当中：API还没有冻结并且这份文档还在完成的过程中或者已过时。我们已经做出了每种努力来清晰地指出还待完成的地方。
  我们在这个时间点发布它，因为它已经足够完整以用于实用，并且提供了一个 Matrix 演化的方式的权威的引用。
  我们的最终目标是成为网页超文本应用技术小组(WHATWG)的 `Living Standard
  <http://wiki.whatwg.org/wiki/FAQ#What_does_.22Living_Standard.22_mean.3F>`_.

Matrix是一套用于开放联盟的即时通信（IM），IP语音（VoIP）和物联网（IoT）通信的开放API，设计于建立并支持一个新的全球实时通信生态系统。目的是为因特网提供一个开放去中心化的发布/订阅（pubsub）层，用于安全地发布/订阅JSON对象。这个规范是不间断地标准化被不同Matrix生态系统组件用来互相交流所使用的API的结果。

Matrix尝试遵循的原则是：

- 务实的对web友好的API（即REST上的JSON）
- 保持简单，且一目了然（Keep It Simple & Stupid）

  + 提供一个使用第三方依赖最少的简单架构。

- 完全开放：

  + 完全开放的联盟——每个人应当可以参与全球Matrix网络
  + 完全开放的标准——带公开文档的标准，没有知识产权或专利授权负担
  + 完全开放源代码的参考实现——自由许可证的样例实现，没有知识产权或专利授权负担

- 授予用户权力

  + 用户应该能够选择他们使用的服务器和客户端
  + 用户应当控制他们的通信有多秘密
  + 用户应当准确地知道他们的数据存储在什么地方

- 完全去中心化——没有单一的控制会话或整个网络的节点
- 从历史获得教训从而避免重复历史

  + 尝试吸取 XMPP, SIP, IRC, SMTP, IMAP 和 NNTP 最好的方面，同时尝试避免它们的的弱点


Matrix提供的功能包括：

- 完全分布式聊天室的创建和管理，没有单点控制或失败
- 在全球开放联盟服务器和服务的网络上的最终一致性的密码学安全的聊天室状态同步
- 在聊天室发送接收可扩展消息，带（可选的）端到端加密
- 基于权力级别的用户权限系统所仲裁的可扩展用户管理（邀请、加入、离开、提出、禁止）
- 可扩展的聊天室状态管理（聊天室命名、别名、话题、禁令）
- 可扩展的用户资料管理（头像、显示的名字等等）
- 管理用户账户（注册、登录、登出）
- 在Matrix上使用第三方ID（3PID）例如邮箱帐号、电话号码、Facebook帐号来认证、识别和发现用户
- 用于以下目的的可信身份服务器联盟：

  + 发布用户密钥用于公钥基础设施（PKI）
  + 3PID到Matrix ID的映射


Matrix的最终目标是成为无所不在的用于在人群、设备和服务集合之间同步任意数据的消息层，可以用于即时通信，VoIP通话的建立，或者其他需要可靠和持续以可互操作和联合的方式从A到B推送的对象。

架构
------------

Matrix 定义了用于同步可扩展 JSON 对象，人们称为在兼容客户端、服务端和服务之间的“事件(event)”的 API。
客户端通常是消息/VoIP应用或者是 IoT 设备/集线器，并且通过使用“客户端-服务端 API”和他们的“homeserver”同步通信历史来交流。
每个homeserver为所有客户端存储通信历史和账户信息，并且通过和其他 homeserver 和它们的客户端同步通信历史的方法和更宽阔的 Matrix 生态系统共享数据。

客户端通常通过在一个虚拟“房间”的上下文下发出事件来相互交流。房间数据在用户参与了这个房间的 *所有的homeserver* 之间复制。
像这样，*没有一个单独的homeserver拥有一个房间的控制或所有权*。
Homeserver将通信历史建模为一个被称为房间的“事件图”的部分有序的事件的图，它会在参与的服务器之间通过使用“服务器-服务器 API”最终一致地同步。
这个在不同homeserver间同步共享交谈历史的过程称为“联盟(Federation)”。
Matrix优化了CAP定理中的可用性和网络分区性，以一致性为代价。

例如，客户端A发送消息给客户端B，客户端A用客户端-服务器API在它的homeserver(HS)上做了一个所需JSON事件的HTTP PUT操作。A的HS把这个事件追加到它的这个房间的事件图的复本上，
为了一致性，在图的上下文中对这个消息签名。接着A的HS用服务器-服务器API做一个HTTP PUT复制这个消息到B的HS上。B的HS认证这个请求，检查这个事件的签名的有效性，对事件的内容授权，然后把它添加到房间事件图的复本上。客户端B接着通过一个长时间存活的GET请求从他的homeserver上接收消息。

::

                         How data flows between clients
                         ==============================

       { Matrix client A }                             { Matrix client B }
           ^          |                                    ^          |
           |  events  |  Client-Server API                 |  events  |
           |          V                                    |          V
       +------------------+                            +------------------+
       |                  |---------( HTTPS )--------->|                  |
       |   homeserver     |                            |   homeserver     |
       |                  |<--------( HTTPS )----------|                  |
       +------------------+      Server-Server API     +------------------+
                              History Synchronisation
                                  (Federation)


用户
~~~~~

每个客户和一个用户帐号关联，它用一个独一无二的“用户ID”在Matrix中被识别。这个ID在分配这个帐号的homeserver的命名空间下，并有如下形式::

  @localpart:domain

见 `标识符语法`_ 一节以获得用户ID结构的完整细节。

事件
~~~~~~

所有在Matrix上交换的数据都被表达为一个“事件(event)”。通常每个客户端操作（如发送一条消息）准确地对应一个事件。
每个事件有一个 ``类型`` 用来区分不同种类的数据。 ``类型`` 值必须独一无二地依据Java的 `包命名约定`_ 放在全局命名空间中，例如
``com.example.myapp.event``. 特殊的顶级命名空间 ``m.`` 被保留用于Matrix规范中定义的事件 —— 例如
``m.room.message`` 是用于即时消息的事件类型。事件通常在一个“房间”的上下文下发送。

.. _包命名约定: https://en.wikipedia.org/wiki/Java_package#Package_naming_conventions

事件图
~~~~~~~~~~~~

.. _sect:event-graph:

在一个房间上下文中交换的事件被存储在一个称为“事件图(event graph)”的有向无环图(DAG)中。
这个图的部分有序性给出了房间中事件的事件顺序。图中的每个事件有一个零个或多个父事件的列表，
它指的是任意从创建这个事件的homeserver的角度上没有时间上后继的在前的事件。

通常一个事件有一个单独的父事件：房间中在它被发出的时候最近的消息。然而，homeserver可能在发送消息的时候合法地互相竞争，
造成了一个单独的事件有多个后继。下一个添加到图中的事件于是就有了多个父事件。
每个事件图有一个没有父事件的根事件。

为了排序及简化图中事件之间时间的比较，homeserver在每个事件维护一个 ``深度`` 元数据字段。
一个事件的 ``深度`` 是一个正整数，它严格大于任何一个父事件的深度。根事件应当有深度1。从而如果一个事件在另一个事件之前，
它就必须有一个严格更小的深度。

房间结构
~~~~~~~~~~~~~~

一个房间是用户可以发送接受事件的一个概念上的地点。事件被发送到房间里，并且所有在那个房间的有足够访问权限的参与者会收到这个事件。
房间被独一无二地在内部通过“房间ID”被标识，它有这样的形式::

  !opaque_id:domain

每个房间有一个房间ID。同时房间ID包含一个域，它是用来做房间ID的全局命名空间的。房间并不属于被指定的那个域。

见 `标识符语法`_ 一节来获取房间ID结构的完整细节。

以下概念性的图表展现了一个
``m.room.message`` 事件，它正在被发送到房间 ``!qporfwt:matrix.org``::

       { @alice:matrix.org }                             { @bob:domain.com }
               |                                                 ^
               |                                                 |
      [HTTP POST]                                  [HTTP GET]
      Room ID: !qporfwt:matrix.org                 Room ID: !qporfwt:matrix.org
      Event type: m.room.message                   Event type: m.room.message
      Content: { JSON object }                     Content: { JSON object }
               |                                                 |
               V                                                 |
       +------------------+                          +------------------+
       |   homeserver     |                          |   homeserver     |
       |   matrix.org     |                          |   domain.com     |
       +------------------+                          +------------------+
               |                                                 ^
               |         [HTTP PUT]                              |
               |         Room ID: !qporfwt:matrix.org            |
               |         Event type: m.room.message              |
               |         Content: { JSON object }                |
               `-------> Pointer to the preceding message  ------`
                         PKI signature from matrix.org
                         Transaction-layer metadata
                         PKI Authorization header

                     ...................................
                    |           Shared Data             |
                    | State:                            |
                    |   Room ID: !qporfwt:matrix.org    |
                    |   Servers: matrix.org, domain.com |
                    |   Members:                        |
                    |    - @alice:matrix.org            |
                    |    - @bob:domain.com              |
                    | Messages:                         |
                    |   - @alice:matrix.org             |
                    |     Content: { JSON object }      |
                    |...................................|

联盟在多个homeserver之间维护每个房间的 *共享数据结构* 。数据被分割为 ``消息事件`` 和 ``状态事件`` 。

消息事件:
  这些描述了房间内短暂的“一次性”活动，例如即时消息、VoIP呼叫建立、文件传输等等。它们通常描述交流活动。

状态事件:
  这些描述了和房间关联的一个给定的持续性信息（“状态”）的更新，例如房间的名字、主题、资格、参与的服务器等等。状态由一个每房间一个的键值对的查找表刻画，每个关键词为一个 ``状态关键字`` 和 ``事件类型`` 的元组。
  每个状态事件更新一个给定关键字的值。

在一个给定时间点的房间状态通过考虑图中所给定事件及其之前的所有事件计算。在事件描述相同状态的时候，一个合并冲突算法会被使用。状态演化算法是传递的并且不以来服务器状态，因为它必须一致地选择相同的事件，不考虑服务器或者接收进来的事件的顺序。事件被原先的服务器签名（签名包括父子关系、类型、深度和载荷散列）并且通过联盟推送到房间里参与的服务器，当前正在使用全连接(full mesh)技术。服务器也可以通过从参与一个房间的其他服务器的联盟请求事件回填(backfill of events).

房间别名
++++++++++++

每个房间同时可以有多个“房间别名”，他们的形式是::

  #room_alias:domain

见 `标识符语法`_ 一节以获得一个房间别名结构的完整细节。

一个房间别名“指向”一个房间ID，并且是人类可读的标签，房间通过它被公布和发现。别名指向的房间ID可以通过访问指定的域获得。注意从一个房间别名到一个房间ID的映射并不是固定的，并且可能随着事件变化去指向一个不同的房间ID。因为这个原因，客户端应当解析房间别名至一个房间ID一次，然后在接下来的请求用那个ID。

在解析一个房间别名的时候，服务器同时会和房间中可以通过其加入的服务器响应。

::

        HTTP GET
   #matrix:domain.com      !aaabaa:matrix.org
           |                    ^
           |                    |
    _______V____________________|____
   |          domain.com            |
   | Mappings:                      |
   | #matrix >> !aaabaa:matrix.org  |
   | #golf   >> !wfeiofh:sport.com  |
   | #bike   >> !4rguxf:matrix.org  |
   |________________________________|

身份标识
~~~~~~~~

Users in Matrix are identified via their Matrix user ID. However,
existing 3rd party ID namespaces can also be used in order to identify Matrix
users. A Matrix "Identity" describes both the user ID and any other existing IDs
from third party namespaces *linked* to their account.
Matrix users can *link* third-party IDs (3PIDs) such as email addresses, social
network accounts and phone numbers to their user ID. Linking 3PIDs creates a
mapping from a 3PID to a user ID. This mapping can then be used by Matrix
users in order to discover the user IDs of their contacts.
In order to ensure that the mapping from 3PID to user ID is genuine, a globally
federated cluster of trusted "Identity Servers" (IS) are used to verify the 3PID
and persist and replicate the mappings.

Usage of an IS is not required in order for a client application to be part of
the Matrix ecosystem. However, without one clients will not be able to look up
user IDs using 3PIDs.


Profiles
~~~~~~~~

Users may publish arbitrary key/value data associated with their account - such
as a human readable display name, a profile photo URL, contact information
(email address, phone numbers, website URLs etc).

.. TODO
  Actually specify the different types of data - e.g. what format are display
  names allowed to be?

Private User Data
~~~~~~~~~~~~~~~~~

Users may also store arbitrary private key/value data in their account - such as
client preferences, or server configuration settings which lack any other
dedicated API.  The API is symmetrical to managing Profile data.

.. TODO
  Would it really be overengineered to use the same API for both profile &
  private user data, but with different ACLs?


标识符语法
------------------

Server Name
~~~~~~~~~~~

A homeserver is uniquely identified by its server name. This value is used in a
number of identifiers, as described below.

The server name represents the address at which the homeserver in question can
be reached by other homeservers. The complete grammar is::

    server_name = dns_name [ ":" port]
    dns_name = host
    port = *DIGIT

where ``host`` is as defined by `RFC3986, section 3.2.2
<https://tools.ietf.org/html/rfc3986#section-3.2.2>`_.

Examples of valid server names are:

* ``matrix.org``
* ``matrix.org:8888``
* ``1.2.3.4`` (IPv4 literal)
* ``1.2.3.4:1234`` (IPv4 literal with explicit port)
* ``[1234:5678::abcd]`` (IPv6 literal)
* ``[1234:5678::abcd]:5678`` (IPv6 literal with explicit port)


Common Identifier Format
~~~~~~~~~~~~~~~~~~~~~~~~

The Matrix protocol uses a common format to assign unique identifiers to a
number of entities, including users, events and rooms. Each identifier takes
the form::

  &localpart:domain

where ``&`` represents a 'sigil' character; ``domain`` is the `server name`_ of
the homeserver which allocated the identifier, and ``localpart`` is an
identifier allocated by that homeserver.

The sigil characters are as follows:

* ``@``: User ID
* ``!``: Room ID
* ``$``: Event ID
* ``#``: Room alias

The precise grammar defining the allowable format of an identifier depends on
the type of identifier.

User Identifiers
++++++++++++++++

Users within Matrix are uniquely identified by their Matrix user ID. The user
ID is namespaced to the homeserver which allocated the account and has the
form::

  @localpart:domain

The ``localpart`` of a user ID is an opaque identifier for that user. It MUST
NOT be empty, and MUST contain only the characters ``a-z``, ``0-9``, ``.``,
``_``, ``=``, and ``-``.

The ``domain`` of a user ID is the `server name`_ of the homeserver which
allocated the account.

The length of a user ID, including the ``@`` sigil and the domain, MUST NOT
exceed 255 characters.

The complete grammar for a legal user ID is::

  user_id = "@" user_id_localpart ":" server_name
  user_id_localpart = 1*user_id_char
  user_id_char = DIGIT
               / %x61-7A                   ; a-z
               / "-" / "." / "=" / "_"

.. admonition:: Rationale

  A number of factors were considered when defining the allowable characters
  for a user ID.

  Firstly, we chose to exclude characters outside the basic US-ASCII character
  set. User IDs are primarily intended for use as an identifier at the protocol
  level, and their use as a human-readable handle is of secondary
  benefit. Furthermore, they are useful as a last-resort differentiator between
  users with similar display names. Allowing the full unicode character set
  would make very difficult for a human to distinguish two similar user IDs. The
  limited character set used has the advantage that even a user unfamiliar with
  the Latin alphabet should be able to distinguish similar user IDs manually, if
  somewhat laboriously.

  We chose to disallow upper-case characters because we do not consider it
  valid to have two user IDs which differ only in case: indeed it should be
  possible to reach ``@user:matrix.org`` as ``@USER:matrix.org``. However,
  user IDs are necessarily used in a number of situations which are inherently
  case-sensitive (notably in the ``state_key`` of ``m.room.member``
  events). Forbidding upper-case characters (and requiring homeservers to
  downcase usernames when creating user IDs for new users) is a relatively simple
  way to ensure that ``@USER:matrix.org`` cannot refer to a different user to
  ``@user:matrix.org``.

  Finally, we decided to restrict the allowable punctuation to a very basic set
  to ensure that the identifier can be used as-is in as wide a number of
  situations as possible, without requiring escaping. For instance, allowing
  "%" or "/" would make it harder to use a user ID in a URI. "*" is used as a
  wildcard in some APIs (notably the filter API), so it also cannot be a legal
  user ID character.

  The length restriction is derived from the limit on the length of the
  ``sender`` key on events; since the user ID appears in every event sent by the
  user, it is limited to ensure that the user ID does not dominate over the actual
  content of the events.

Matrix user IDs are sometimes informally referred to as MXIDs.

Historical User IDs
<<<<<<<<<<<<<<<<<<<

Older versions of this specification were more tolerant of the characters
permitted in user ID localparts. There are currently active users whose user
IDs do not conform to the permitted character set, and a number of rooms whose
history includes events with a ``sender`` which does not conform. In order to
handle these rooms successfully, clients and servers MUST accept user IDs with
localparts from the expanded character set::

  extended_user_id_char = %x21-7E

Mapping from other character sets
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

In certain circumstances it will be desirable to map from a wider character set
onto the limited character set allowed in a user ID localpart. Examples include
a homeserver creating a user ID for a new user based on the username passed to
``/register``, or a bridge mapping user ids from another protocol.

.. TODO-spec

   We need to better define the mechanism by which homeservers can allow users
   to have non-Latin login credentials. The general idea is for clients to pass
   the non-Latin in the ``username`` field to ``/register`` and ``/login``, and
   the HS then maps it onto the MXID space when turning it into the
   fully-qualified ``user_id`` which is returned to the client and used in
   events.

Implementations are free to do this mapping however they choose. Since the user
ID is opaque except to the implementation which created it, the only
requirement is that the implemention can perform the mapping
consistently. However, we suggest the following algorithm:

1. Encode character strings as UTF-8.

2. Convert the bytes ``A-Z`` to lower-case.

   * In the case where a bridge must be able to distinguish two different users
     with ids which differ only by case, escape upper-case characters by
     prefixing with ``_`` before downcasing. For example, ``A`` becomes
     ``_a``. Escape a real ``_`` with a second ``_``.

3. Encode any remaining bytes outside the allowed character set, as well as
   ``=``, as their hexadecimal value, prefixed with ``=``. For example, ``#``
   becomes ``=23``; ``á`` becomes ``=c3=a1``.

.. admonition:: Rationale

  The suggested mapping is an attempt to preserve human-readability of simple
  ASCII identifiers (unlike, for example, base-32), whilst still allowing
  representation of *any* character (unlike punycode, which provides no way to
  encode ASCII punctuation).


Room IDs and Event IDs
++++++++++++++++++++++

A room has exactly one room ID. A room ID has the format::

  !opaque_id:domain

An event has exactly one event ID. An event ID has the format::

  $opaque_id:domain

The ``domain`` of a room/event ID is the `server name`_ of the homeserver which
created the room/event. The domain is used only for namespacing to avoid the
risk of clashes of identifiers between different homeservers. There is no
implication that the room or event in question is still available at the
corresponding homeserver.

Event IDs and Room IDs are case-sensitive. They are not meant to be human
readable.

.. TODO-spec
  What is the grammar for the opaque part? https://matrix.org/jira/browse/SPEC-389

Room Aliases
++++++++++++

A room may have zero or more aliases. A room alias has the format::

      #room_alias:domain

The ``domain`` of a room alias is the `server name`_ of the homeserver which
created the alias. Other servers may contact this homeserver to look up the
alias.

Room aliases MUST NOT exceed 255 bytes (including the ``#`` sigil and the
domain).

.. TODO-spec
  - Need to specify precise grammar for Room Aliases. https://matrix.org/jira/browse/SPEC-391


License
-------

The Matrix specification is licensed under the `Apache License, Version 2.0
<http://www.apache.org/licenses/LICENSE-2.0>`_.
